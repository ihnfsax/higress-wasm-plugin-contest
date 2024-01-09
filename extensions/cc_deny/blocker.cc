#include "extensions/cc_deny/blocker.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <numeric>

#include "absl/strings/match.h"
#include "absl/strings/str_format.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace ip_deny {

#endif

bool Blocker::isBlocked(const CCDenyConfigRule &rule, const std::string &key) {
  WasmDataPtr shared_data;
  uint32_t cas;
  WasmResult get_res, set_res;
  MaxQuery constraint;
  uint16_t block_seconds;

  if (absl::StartsWith(key, cookie_key)) {
    constraint = rule.cookie_max;
    block_seconds = rule.cookie_block_seconds;
  } else {
    constraint = rule.header_max;
    block_seconds = rule.header_block_seconds;
  }

  for (size_t i = 0; i < max_retry; i++) {
    get_res = getSharedData(key, &shared_data, &cas);

    if (WasmResult::NotFound == get_res) {
      Window window = {};
      // window.is_blocked = false;
      window.last_time = getCurrentTimeNanoseconds();
      window.one_second[0] = 1;
      window.one_minute[0] = 1;
      window.one_hour[0] = 1;
      setSharedWindowData(key, window, cas);
      return false;
    }

    if (get_res == WasmResult::CasMismatch) {
      continue;
    } else if (get_res != WasmResult::Ok) {
      LOG_WARN(absl::StrFormat("get shared data failed, key:%s, res:%d", key,
                               get_res));
      return false;
    }

    Window window = *reinterpret_cast<const Window *>(shared_data->data());

    uint64_t current_time = getCurrentTimeNanoseconds();

    // if (window.is_blocked && block_seconds > 0) {
    //   if (current_time - window.earliest_block_time >=
    //       block_seconds * second_nano) {
    //     window.is_blocked = false;
    //   } else {
    //     return true;
    //   }
    // }

    bool is_blocked = false;

    if (constraint.qps != 0) {
      is_blocked |= isBlockedByQPS(constraint, window, current_time);
    }

    if (constraint.qpm != 0) {
      is_blocked |= isBlockedByQPM(constraint, window, current_time);
    }

    if (constraint.qpd != 0) {
      is_blocked |= isBlockedByQPD(constraint, window, current_time);
    }

    window.last_time = current_time;

    // if (window.is_blocked == false && is_blocked == true) {  // first block
    //   window.earliest_block_time = current_time;
    // }
    // window.is_blocked = is_blocked;

    if (setSharedWindowData(key, window, cas)) {
      return is_blocked;
    } else {
      return false;
    }
  }

  LOG_WARN(absl::StrFormat("get shared data reach max times, key:%s, res:%d",
                           key, get_res));
  return false;
}

bool Blocker::setSharedWindowData(const std::string &key, const Window &window,
                                  uint32_t &cas) {
  WasmResult set_res;
  for (size_t j = 0; j < max_retry; j++) {
    set_res = setSharedData(
        key, {reinterpret_cast<const char *>(&window), sizeof(window)});

    if (set_res == WasmResult::CasMismatch) {
      continue;  // reset again
    } else if (set_res == WasmResult::Ok) {
      return true;  // set success
    }
    LOG_WARN(absl::StrFormat("set shared data failed, key:%s, res:%d", key,
                             set_res));
    return false;
  }
  LOG_WARN(absl::StrFormat("set shared data reach max times, key:%s, res:%d",
                           key, set_res));
  return false;
}

bool Blocker::isBlockedByQPS(const MaxQuery &constraint, Window &window,
                             const uint64_t &current_time) {
  uint64_t last_slice_number = window.last_time / second_slice_nano;
  uint64_t current_slice_number = current_time / second_slice_nano;

  if (current_slice_number > last_slice_number) {
    uint64_t diff = current_slice_number - last_slice_number;
    if (diff > SECOND_SLICE_NUM) {  // diff is bigger than one second
      memset(window.one_second, 0, SECOND_SLICE_NUM);
      window.one_second[0] = 1;
      LOG_INFO(absl::StrFormat("qps pass, diff: %ld", diff));
      return false;
    }

    // shift array elements
    memmove(&window.one_second[diff], &window.one_second[0],
            sizeof(uint16_t) * (SECOND_SLICE_NUM - diff));
    memset(&window.one_second[0], 0, sizeof(uint16_t) * diff);
  }

  window.one_second[0]++;

  uint32_t total_count = std::accumulate(std::begin(window.one_second),
                                         std::end(window.one_second), 0);

  if (total_count > constraint.qps) {
    window.one_second[0]--;
    LOG_INFO(absl::StrFormat("denied by qps, total_count:%d, constraint:%d",
                             total_count - 1, constraint.qps));
    return true;
  }
  LOG_INFO(absl::StrFormat("qps pass, total_count:%d, constraint:%d",
                           total_count, constraint.qps));
  return false;
}

bool Blocker::isBlockedByQPM(const MaxQuery &constraint, Window &window,
                             const uint64_t &current_time) {
  uint64_t last_slice_number = window.last_time / minute_slice_nano;
  uint64_t current_slice_number = current_time / minute_slice_nano;

  if (current_slice_number > last_slice_number) {
    uint64_t diff = current_slice_number - last_slice_number;
    if (diff > MINUTE_SLICE_NUM) {  // diff is bigger than one minute
      memset(window.one_minute, 0, MINUTE_SLICE_NUM);
      window.one_minute[0] = 1;
      LOG_INFO(absl::StrFormat("qpm pass, diff: %ld", diff));
      return false;
    }

    // shift array elements
    memmove(&window.one_minute[diff], &window.one_minute[0],
            sizeof(uint16_t) * (MINUTE_SLICE_NUM - diff));
    memset(&window.one_minute[0], 0, sizeof(uint16_t) * diff);
  }

  window.one_minute[0]++;

  uint32_t total_count = std::accumulate(std::begin(window.one_minute),
                                         std::end(window.one_minute), 0);

  if (total_count > constraint.qpm) {
    window.one_minute[0]--;
    LOG_INFO(absl::StrFormat("denied by qpm, total_count:%d, constraint:%d",
                             total_count - 1, constraint.qpm));
    return true;
  }
  LOG_INFO(absl::StrFormat("qpm pass, total_count:%d, constraint:%d",
                           total_count, constraint.qpm));
  return false;
}

bool Blocker::isBlockedByQPD(const MaxQuery &constraint, Window &window,
                             const uint64_t &current_time) {
  uint64_t last_slice_number = window.last_time / hour_slice_nano;
  uint64_t current_slice_number = current_time / hour_slice_nano;

  if (current_slice_number > last_slice_number) {
    uint64_t diff = current_slice_number - last_slice_number;
    if (diff > HOUR_SLICE_NUM) {  // diff is bigger than one hour
      memset(window.one_hour, 0, HOUR_SLICE_NUM);
      window.one_hour[0] = 1;
      LOG_INFO(absl::StrFormat("qpd pass, diff: %ld", diff));
      return false;
    }

    // shift array elements
    memmove(&window.one_hour[diff], &window.one_hour[0],
            sizeof(uint16_t) * (HOUR_SLICE_NUM - diff));
    memset(&window.one_hour[0], 0, sizeof(uint16_t) * diff);
  }

  window.one_hour[0]++;

  uint32_t total_count = std::accumulate(std::begin(window.one_hour),
                                         std::end(window.one_hour), 0);

  if (total_count > constraint.qpd) {
    window.one_hour[0]--;
    LOG_INFO(absl::StrFormat("denied by qpd, total_count:%d, constraint:%d",
                             total_count - 1, constraint.qpd));
    return true;
  }
  LOG_INFO(absl::StrFormat("qpd pass, total_count:%d, constraint:%d",
                           total_count, constraint.qpm));
  return false;
}

#ifdef NULL_PLUGIN

}  // namespace ip_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif