load("@rules_python//python:defs.bzl", "py_binary")
load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_fuzz_test",
    "envoy_cc_test_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

H1_FUZZ_LIB_DEPS = [
    "//test/integration:capture_fuzz_proto_cc_proto",
    "//test/integration:http_integration_lib",
    "//source/common/common:assert_lib",
    "//source/common/common:logger_lib",
    "//test/fuzz:fuzz_runner_lib",
    "//test/integration:integration_lib",
    "//test/test_common:environment_lib",
]

envoy_cc_test_library(
    name = "h1_fuzz_persistent_lib",
    srcs = ["h1_fuzz.cc"],
    hdrs = ["h1_fuzz.h"],
    copts = ["-DPERSISTENT_FUZZER"],
    deps = H1_FUZZ_LIB_DEPS,
)

envoy_cc_fuzz_test(
    name = "h1_diff_fuzz_test",
    srcs = ["h1_diff_fuzz_test.cc"],
    copts = ["-DPERSISTENT_FUZZER"],
    corpus = "h1_corpus",
    deps = [":h1_fuzz_persistent_lib"],
)
