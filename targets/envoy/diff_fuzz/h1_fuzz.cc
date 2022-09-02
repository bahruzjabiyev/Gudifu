#include "test/integration/diff_fuzz/h1_fuzz.h"

#include <functional>

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"

#include "test/integration/http_integration.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

namespace Envoy {

namespace {

//TODO: if there is a replace function of absl which replaces only one
//occurence, then use that instead
bool replace(std::string& str, const std::string& from, const std::string& to) {
  const size_t start_pos = str.find(from);
  if(start_pos == std::string::npos)
    return false;
  str.replace(start_pos, from.length(), to);
  return true;
}

std::string lower(std::string& str) {
  std::string result_str = str;
  for(auto& c : result_str) {
    c = tolower(c);
  }

  return result_str;
}

void addHash(std::string& request, const std::string& hash) {
  std::string request_lower = lower(request);
  // If request has no body, add hash as a body
  if (request_lower.find("\r\n\r\n") + 4 == request_lower.length()) {
    std::string body = absl::StrCat("hash-", hash);

    // Remove existing content-length headers in input, makes no sense anyway
    // without a body
    int pos_cl = 0;
    while(true) {
      request_lower = lower(request);
      pos_cl = request_lower.find("content-length");
      if (pos_cl == -1) break;
      replace(request, request.substr(pos_cl, 14), "invalid-header");
    }

    // Remove existing transfer-encoding headers in input, makes no sense anyway
    // without a body
    int pos_te = 0;
    while(true) {
      request_lower = lower(request);
      pos_te = request_lower.find("transfer-encoding");
      if (pos_te == -1) break;
      replace(request, request.substr(pos_te, 17), "invalid-header");
    }

    // Add new content-length header with the value of the new body which
    // contains the hash
    replace(request, "\r\n\r\n", absl::StrCat("\r\ncontent-length: 45\r\n\r\n", body));
  } else { // just add in the end of headers block
    replace(request, "\r\n\r\n", absl::StrCat("\r\nvia: hash-", hash, "\r\n\r\n"));
  }
}

} // namespace

void H1FuzzIntegrationTest::replayDiff(const std::string &input, const std::string &request_sha_hash) {
  PERSISTENT_FUZZ_VAR bool initialized = [this]() -> bool {
    initialize();
    return true;
  }();
  UNREFERENCED_PARAMETER(initialized);
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("http"));
  FakeRawConnectionPtr fake_upstream_connection;
  if (!tcp_client->connected()) {
    ENVOY_LOG_MISC(debug, "Disconnected, no further event processing.");
  }

  std::string mutable_input = input;
  // Adding the hash of the request as a header
  addHash(mutable_input, request_sha_hash);

  ASSERT_TRUE(tcp_client->write(mutable_input, false, false));
  tcp_client->close();
}

} // namespace Envoy
