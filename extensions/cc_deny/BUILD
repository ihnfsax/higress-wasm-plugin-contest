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
load("//bazel:wasm.bzl", "declare_wasm_image_targets")

wasm_cc_binary(
    name = "cc_deny.wasm",
    srcs = [
        "blocker.cc",
        "blocker.h",
        "plugin.cc",
        "plugin.h",
    ],
    copts = [
        "-funroll-loops",
        "-fno-rtti",
        "-fno-exceptions",
        "-finline-functions",
        "-fomit-frame-pointer",
    ],
    deps = [
        "//common:http_util",
        "//common:json_util",
        "//common:rule_util",
        "@com_google_absl//absl/numeric:int128",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@proxy_wasm_cpp_sdk//:proxy_wasm_intrinsics",
    ],
)

cc_library(
    name = "cc_deny_lib",
    srcs = [
        "blocker.cc",
        "plugin.cc",
    ],
    hdrs = [
        "blocker.h",
        "plugin.h",
    ],
    copts = ["-DNULL_PLUGIN"],
    deps = [
        "//common:http_util_nullvm",
        "//common:json_util",
        "//common:rule_util_nullvm",
        "@com_google_absl//absl/strings",
        "@proxy_wasm_cpp_host//:lib",
    ],
)

declare_wasm_image_targets(
    name = "cc_deny",
    wasm_file = ":cc_deny.wasm",
)
