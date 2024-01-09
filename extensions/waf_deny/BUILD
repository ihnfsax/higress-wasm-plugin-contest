# Copyright (c) 2022 Alibaba Group Holding Ltd.
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

load("@proxy_wasm_cpp_sdk//bazel/wasm:wasm.bzl", "wasm_cc_binary")
load("@com_google_protobuf//:protobuf.bzl", "cc_proto_library")
load("//bazel:wasm.bzl", "declare_wasm_image_targets")

wasm_cc_binary(
    name = "waf_deny.wasm",
    srcs = [
        "plugin.cc",
        "plugin.h",
        "rule_filter.cc",
        "rule_filter.h",
        "rule_set.cc",
        "rule_set.h",
        "static_rules.cc",
        "static_rules.h",
        "transaction.cc",
        "transaction.h",
        "util.cc",
        "util.h",
    ] + glob([
        "transformations/*.cc",
        "transformations/*.h",
        "matchers/*.cc",
        "matchers/*.h",
    ]),
    copts = [
        "-funroll-loops",
        "-fno-rtti",
        "-fno-exceptions",
        "-finline-functions",
        "-fomit-frame-pointer",
    ],
    deps = [
        ":rules_message",
        "//common:http_util",
        "//common:json_util",
        "//common:regex_util",
        "//common:rule_util",
        "@com_google_protobuf//:protobuf",
        "@proxy_wasm_cpp_sdk//:proxy_wasm_intrinsics",
    ],
)

cc_proto_library(
    name = "rules_message",
    srcs = ["rules_message.proto"],
)

cc_binary(
    name = "transformation_test",
    srcs = [
        "transformation.cc",
        "transformation.h",
        "transformation_test.cc",
    ],
    copts = ["-DNULL_PLUGIN"],
)

declare_wasm_image_targets(
    name = "waf_deny",
    wasm_file = ":waf_deny.wasm",
)
