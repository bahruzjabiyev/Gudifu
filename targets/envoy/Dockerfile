# Copyright 2022 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################


FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get -y install  \
	build-essential \
	openjdk-8-jdk   \
	make            \
    ninja-build     \
    curl            \
    autoconf        \
    libtool         \
    wget            \
    golang          \
    rsync

RUN git clone https://github.com/envoyproxy/envoy.git
WORKDIR $SRC/envoy/
ADD diff_fuzz $SRC/envoy/test/integration/diff_fuzz
ADD h1_corpus $SRC/envoy/test/integration/diff_fuzz/h1_corpus

COPY build.sh $SRC/
RUN /usr/local/bin/compile_libfuzzer
