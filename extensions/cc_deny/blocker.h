#ifndef EXTENSIONS_CC_DENY_BLOCKER_H
#define EXTENSIONS_CC_DENY_BLOCKER_H

#include <cstdint>
#include <string>

#ifndef NULL_PLUGIN

#include "proxy_wasm_intrinsics.h"

#else

#include "include/proxy-wasm/null_plugin.h"

using proxy_wasm::WasmResult;

namespace proxy_wasm {
namespace null_plugin {
namespace cc_deny {

#endif

#define SECOND_SLICE_NUM 30
#define MINUTE_SLICE_NUM 60
#define HOUR_SLICE_NUM 24

// Max retry times for get and set shared data.
const size_t max_retry = 20;

const uint64_t second_nano = 1000000000;
const uint64_t minute_nano = 60 * second_nano;
const uint64_t day_nano = 24 * minute_nano * 60;

const uint64_t second_slice_nano = second_nano / SECOND_SLICE_NUM;
const uint64_t minute_slice_nano = minute_nano / MINUTE_SLICE_NUM;
const uint64_t hour_slice_nano = day_nano / HOUR_SLICE_NUM;

struct Window {
  // bool is_blocked;
  uint64_t last_time;
  // uint64_t earliest_block_time;
  uint16_t one_second[SECOND_SLICE_NUM];
  uint16_t one_minute[MINUTE_SLICE_NUM];
  uint16_t one_hour[HOUR_SLICE_NUM];
};

struct MaxQuery {
  uint16_t qps;
  uint16_t qpm;
  uint16_t qpd;
};

struct CCDenyConfigRule {
  std::string header_type;
  std::string cookie_type;
  MaxQuery header_max;
  MaxQuery cookie_max;
  uint16_t header_block_seconds;
  uint16_t cookie_block_seconds;
};

const std::string cookie_key = "cookie";
const std::string header_key = "header";

class Blocker {
 public:
  Blocker() {}
  ~Blocker() {}

  static bool isBlocked(const CCDenyConfigRule& rule, const std::string& key);

 private:
  static uint64_t getCurrentTimeNanoseconds() {
    uint64_t t;
    CHECK_RESULT(proxy_get_current_time_nanoseconds(&t));
    return t;
  }

  // return true if set shared data success.
  static bool setSharedWindowData(const std::string& key, const Window& window,
                                  uint32_t& cas);

  static bool isBlockedByQPS(const MaxQuery& constraint, Window& window,
                             const uint64_t& current_time);

  static bool isBlockedByQPM(const MaxQuery& constraint, Window& window,
                             const uint64_t& current_time);

  static bool isBlockedByQPD(const MaxQuery& constraint, Window& window,
                             const uint64_t& current_time);
};

#ifdef NULL_PLUGIN

}  // namespace cc_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif

#endif  // EXTENSIONS_CC_DENY_BLOCKER_H