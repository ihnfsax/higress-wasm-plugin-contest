# IP Deny Plugin

IP 黑名单拦截所有 `x-real-ip` 请求头为配置中指定的 IP 地址/范围的 HTTP 报文。

## Setup

编译插件：

```bash
bazel build //extensions/ip_deny:ip_deny.wasm
```

可用配置：

```json
{
  "ip_blacklist": [
    "1.1.1.1",
    "10.2.0.0/16"
  ]
}
```

## Features

本插件采用**红黑树**存储 IP 范围，类似于 Interval Tree。导入配置时，插件会自动合并范围，降低未来的查询开销。

Note: 本插件仅支持 IPv4。
