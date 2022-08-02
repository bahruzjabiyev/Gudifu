// NGINX http autofuzz implementation
//
// NGINX is multi-process scaleable reverse proxy. The overall architecture
// makes it hard to fuzz in-process but coverage and speed will likely be much
// better. Given it is a bit hacky, any crash should be reviewed carefully to
// ensure that the issue could happen on a real deployment.

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <atomic>
#include <iostream>
#include <string>

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "http_request_proto.pb.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "libfuzzer/FuzzerSHA1.h"

extern "C" {
  #include <ngx_config.h>
  #include <ngx_core.h>
  #include <ngx_event.h>
  #include <ngx_http.h>
  #include <ngx_connection.h>
  #include <ngx_inet.h>
  #include <nginx.h>
  #include "libfuzzer/FuzzerSHA1.h"
}

std::string configuration_str1 =
"error_log /tmp/errors debug;\n"
"pid /tmp/nginx.pid;\n"
"master_process off;\n"
"daemon off;\n"
"events {\n"
"    use epoll;\n"
"    multi_accept off;\n"
"    accept_mutex off;\n"
"}\n"
"http {\n"
"    server_tokens off;\n"
"    error_log /tmp/errors debug;\n"
"    access_log off;\n"
"    client_body_temp_path /tmp/;\n"
"    proxy_temp_path /tmp/;\n"
"    fastcgi_temp_path /tmp/;\n"
"    scgi_temp_path /tmp/;\n"
"    uwsgi_temp_path /tmp/;\n"
"    proxy_buffering off;\n"
"    proxy_ignore_client_abort on;\n"
"server {\n"
"  listen unix:";

std::string configuration_str2 = ";\n"
"  location / {\n"
"    proxy_pass http://172.17.0.1:8002/;\n"
"    proxy_buffering off;\n"
"    proxy_set_header Via       $http_via;\n"
"  }\n"
"}\n"
"}\n"
"";

static std::string unix_socket_path;

extern char **environ;

bool FileExists(const std::string& name) {
    if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }
}

void WriteToFile(const std::string &Data, const std::string &Path, bool check_if_exists) {
  if (check_if_exists) {
    if (FileExists(Path)) return;
  }
  FILE *Out = fopen(Path.c_str(), "wb");
  if (!Out) return;
  const uint8_t *data_uint = reinterpret_cast<const uint8_t *>(Data.c_str());
  fwrite(data_uint, sizeof(data_uint[0]), Data.size(), Out);
  fclose(Out);
}

// Nginx will fail if the unix domain path is longer than 100 characters
std::string GenerateUnixDomainPath(std::string path) {
  static std::atomic<int> count{0};
  int pid = static_cast<int>(getpid());
  std::string ret;
  do {
    std::string filename = "ngxsck" + std::to_string(pid) + "-" + std::to_string(++count);
    ret = path + filename;
  } while (FileExists(ret));
  return ret;
}

// This function generates a configuration with a unique unix socket. Nginx
// requires a configuration file on the disk to work.
std::string WriteConfiguration(void) {
  auto test_tmpdir = "/tmp/";
  unix_socket_path = GenerateUnixDomainPath(test_tmpdir);
  std::string config_content = configuration_str1 + unix_socket_path + configuration_str2; //uncomment
  WriteToFile(config_content, "/tmp/tmpnginxconfig", false);
  return "/tmp/tmpnginxconfig";
}

// A function called by a create thread that will run nginx inside the single thread
void* run_ngx_main_thread(void*) {
  std::string config_file = WriteConfiguration();
  const int my_argc = 5;
  const char *my_argv[] = {
    "/tmp/nginx",
    "-c",
    config_file.c_str(),
    "-e",
    "/tmp/nginx.log",
    NULL
  };

  // This will run the ngx in a single process mode, and in our case in a single
  // thread.
  fuzz_without_main(my_argc, const_cast<char* const *>(my_argv));

  // Should never reach.
  //CHECK(false);
  return NULL;
}


void error(const char *msg) { perror(msg); exit(0); }

bool replace(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}

void sendRequest(const char* message, size_t data_len, const std::string& request_sha_hash) {
  struct sockaddr_un serv_addr;
  int sockfd, bytes, sent;

  std::string message_str = std::string(message, data_len);// + "Host: localhost\r\ncontent-length: 0\r\n\r\n";
  replace(message_str, "1.1\r\n", "1.1\r\nvia: hash-" + request_sha_hash + "\r\n");
  replace(message_str, "ost\r\n", "ost\r\nvia: hash-" + request_sha_hash + "\r\n");
  replace(message_str, ": 0\r\n", ": 0\r\nvia: hash-" + request_sha_hash + "\r\n");

  //std::string tmp_message = message_str;
  //replace(message_str, "\r\n", "\nvia: hash-" + request_sha_hash + "\r\n");
  std::cout << "here is the request: " << message_str << "\n";

  /* create the socket */
  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0) error("ERROR opening socket");

  /* fill in the structure */
  memset(&serv_addr,0,sizeof(serv_addr));
  serv_addr.sun_family = AF_UNIX;
  strcpy(serv_addr.sun_path, unix_socket_path.c_str());

  /* connect the socket */
  if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
      error("ERROR connecting");

  /* send the request */
  const char* hashed_message = message_str.c_str();
  size_t hashed_message_len = message_str.length();
  sent = 0;
  do {
      bytes = write(sockfd,hashed_message+sent,hashed_message_len-sent);
      if (bytes < 0)
          error("ERROR writing message to socket");
      if (bytes == 0)
          break;
      sent+=bytes;
  } while (sent < hashed_message_len);

  // Give nginx another second to process the request.
  sleep(1);

  /* close the socket */
  close(sockfd);
}

bool start_nginx(){
  pthread_t nginx_thread;
  pthread_create(&nginx_thread, NULL, &run_ngx_main_thread, NULL);
  sleep(1);
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t data_len) {

  static bool nginx_started = start_nginx();
  if(!nginx_started) {
    printf("err: nginx is not running!\n");
  }

  //uint8_t Hash[fuzzer::kSHA1NumBytes];
  //fuzzer::ComputeSHA1(data, data_len, Hash);
  //const std::string request_sha_str = fuzzer::Sha1ToString(Hash);
  const std::string request_sha_str = "abcdef";

  // Simulate sending a request.
  sendRequest((const char*) data, data_len, request_sha_str);

  WriteToFile(std::string((const char*) data, data_len), "/tmp/inputs/nginx_"+request_sha_str, true);
  return 0;
}
