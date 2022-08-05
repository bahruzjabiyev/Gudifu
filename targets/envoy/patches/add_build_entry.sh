#!/bin/bash
echo '
envoy_cc_fuzz_test(
    name = "h1_diff_fuzz_test",
    srcs = ["h1_diff_fuzz_test.cc"],
    copts = ["-DPERSISTENT_FUZZER"],
    corpus = "h1_corpus",
    deps = [":h1_fuzz_persistent_lib"],
)
' >> $SRC/envoy/test/integration/BUILD
