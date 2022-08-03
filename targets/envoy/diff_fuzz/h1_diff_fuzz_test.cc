#include "test/integration/h1_fuzz.h"
//#include "third_party/llvm/llvm-project/compiler-rt/lib/fuzzer/FuzzerSHA1.h"

namespace Envoy {

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

bool FileExists(const std::string& name) {
    if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }   
}

void WriteToFile(const std::string &Data, const std::string &Path) {
  if (FileExists(Path)) return;
  FILE *Out = fopen(Path.c_str(), "wb");
  if (!Out) return;
  const uint8_t *data_uint = reinterpret_cast<const uint8_t *>(Data.c_str());
  fwrite(data_uint, sizeof(data_uint[0]), Data.size(), Out);

}

DEFINE_FUZZER(const uint8_t* input, size_t len) {
  // Pick an IP version to use for loopback,, it does not matter which.
  RELEASE_ASSERT(!TestEnvironment::getIpVersionsForTest().empty(), "");
  const auto ip_version = TestEnvironment::getIpVersionsForTest()[0];
  PERSISTENT_FUZZ_VAR H1FuzzIntegrationTest h1_fuzz_integration_test(ip_version);
  //uint8_t Hash[fuzzer::kSHA1NumBytes];
  //fuzzer::ComputeSHA1(input, len, Hash);
  //const std::string request_sha_str = fuzzer::Sha1ToString(Hash);
  const std::string request_sha_str = "abcdef";
  h1_fuzz_integration_test.replay_diff(std::string(reinterpret_cast<const char*>(input),len), request_sha_str);
  WriteToFile(std::string(reinterpret_cast<const char*>(input),len), "/tmp/inputs/envoy_"+request_sha_str);
}

} // namespace Envoy
