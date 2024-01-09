# CC Deny Plugin

CC 防护插件（限流器）用于阻止某一用户超出配置数量的 HTTP 请求。

## Setup

编译插件：

```bash
bazel build //extensions/cc_deny:cc_deny.wasm
```

可用配置：

```json
{
  "cc_rules": [
  {
      "header": "user-agent",
      "qps": 10,
      "qpm": 100,
      "qpd": 1000,
      "block_seconds": 300
    },
    {
      "cookie": "uid",
      "qpm": 100
    }
  ] 
}
```

## Features

本插件使用**滑动小窗口**方法实现限流器。令牌桶面对突发流量时会失效，**滑动小窗口**一定程度上避免了该问题。

该插件目前不支持小黑屋功能（因为线上评测时出现问题）。
