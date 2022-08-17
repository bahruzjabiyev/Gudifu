//TODO: avoid including a copy, instead include the original one
#include "test/integration/diff_fuzz/h1_fuzz.h"
//TODO: replace openssl dependency with something lighter
#include "openssl/sha.h"
#include "test/test_common/utility.h"

namespace Envoy {

namespace {

bool fileExists(const std::string& name) {
  if (FILE *file = fopen(name.c_str(), "r")) {
    fclose(file);
    return true;
  } else {
    return false;
  }
}

void writeToFile(const std::string &data, const std::string &path) {
  if (fileExists(path)) {
    return;
  }
  FILE *out = fopen(path.c_str(), "wb");
  RELEASE_ASSERT(out != nullptr, absl::StrCat(path, " file cannot be opened"));
  const uint8_t *data_uint = reinterpret_cast<const uint8_t *>(data.c_str());
  fwrite(data_uint, sizeof(data_uint[0]), data.size(), out);
}

std::string sha1ToString(uint8_t sha1_hash[SHA_DIGEST_LENGTH]) {
  std::stringstream ss;
  for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(sha1_hash[i]);
  return ss.str();
}

} // namespace


void H1FuzzIntegrationTest::initialize() {
  config_helper_.addConfigModifier([&](envoy::config::bootstrap::v3::Bootstrap& bootstrap) -> void {
    const std::string filter_chain_yaml = R"EOF(
        name: boo
        filters:
        - name: http
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
            stat_prefix: ingress_http
            codec_type: AUTO
            route_config:
              name: local_route
              virtual_hosts:
              - name: local_service
                domains: ["*"]
                routes:
                - route:
                    cluster: echo_service
                  match:
                    prefix: /
            http_filters:
            - name: envoy.filters.http.router
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
    )EOF";

    const std::string cluster_yaml_echo = R"EOF(
      name: echo_service
      connect_timeout: 0.25s
      type: STATIC
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: echo_service
        endpoints:
        - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: 127.0.0.1
                  port_value: 8001
    )EOF";

    auto* filter_chain_template_ = bootstrap.mutable_static_resources()->mutable_listeners(0)->mutable_filter_chains(0);
    TestUtility::loadFromYaml(filter_chain_yaml, *filter_chain_template_);
    auto* cluster_template_2 = bootstrap.mutable_static_resources()->add_clusters();
    TestUtility::loadFromYaml(cluster_yaml_echo, *cluster_template_2);
    bootstrap.mutable_dynamic_resources()->Clear();
  });

  BaseIntegrationTest::use_lds_ = false;
  HttpIntegrationTest::initialize();
}

DEFINE_FUZZER(const uint8_t* input, size_t len) {
  // Pick an IP version to use for loopback,, it does not matter which.
  RELEASE_ASSERT(!TestEnvironment::getIpVersionsForTest().empty(), "");
  const auto ip_version = TestEnvironment::getIpVersionsForTest()[0];
  PERSISTENT_FUZZ_VAR H1FuzzIntegrationTest h1_fuzz_integration_test(ip_version);
  unsigned char request_sha[SHA_DIGEST_LENGTH];
  SHA1(input, len, request_sha);
  std::string request_sha_str = sha1ToString(request_sha);
  h1_fuzz_integration_test.replayDiff(std::string(reinterpret_cast<const char*>(input),len), request_sha_str);
  writeToFile(std::string(reinterpret_cast<const char*>(input),len), "/tmp/input_envoy_"+request_sha_str);
}

} // namespace Envoy
