# Waf Deny Plugin

WAF (Web application firewall) 插件通过过滤阻止任何恶意的 HTTP/S 流量进入 Web 应用程序。

## 编译与使用

编译插件：

```shell
bazel build //extensions/waf_deny:waf_deny.wasm
```

将编译产物移动为 `wasmdemo/main.wasm`。

设置插件配置：

```json
{
  "rule_server" : "rule_server",
  "enabled_rules": {
    "filename" : [
      "**/*.yaml",
      "**/*.yml"
    ]
  }
}
```

使用上述配置，插件启动后会加载所有可用的 WAF 规则。

在 `wasmdemo` 目录下启动服务：

```shell
docker compose up
```

使用 [gotestwaf](https://github.com/wallarm/gotestwaf) 进行测试：

```shell
docker run --rm --network="host" -it wallarm/gotestwaf --url=http://127.0.0.1:10000
```

## WAF 规则

WAF 规则由 YAML 文件定义，每个文件包含一个或多个规则。一个规则文件的示例如下：

```yaml
version: v1.0.0
kind: CRS Protocal Enforcement
rules:
  - id: 920350
    payload: |
      (?:^([\d.]+|\[[\da-f:]+\]|[\da-f:]+)(:[\d]+)?$)
    matchType: regex
    action: deny
    placeholders:
      - HeaderValue:Host
    transformations:
      - Base64
      - URL
      - Base64|URL
    tags:
      - attack-protocol
      - OWASP_CRS/4.0.0-rc1
  - id: 920440
    payload: |
      \.([^.]+)$
    matchType: regex
    action: deny
    placeholders:
      - URLBasename
    transformations:
      - Base64
      - URL
      - Base64|URL
    tags: OWASP_CRS/4.0.0-rc1
```

规则文件内容由元数据和规则列表两部分组成。`version` 和 `kind` 是目前版本支持的元数据，它们都应为一个字符串。`rules` 是规则列表，每个列表元素表示一条规则。一条规则内包含以下字段：

- `id`：规则 ID，必须为一个自然数，必须全局唯一。
- `payload`：字符串，一般表示要匹配的恶意代码，具体使用方式由 `matchType` 字段决定。
- `matchType`：字符串，表示匹配方式，目前支持：
  - `text`：若报文字段包含 `payload` 字段中的字符串，则匹配成功。
  - `regex`：若报文字段的部分内容与 `payload` 字段中的正则表达式匹配，则匹配成功。
  - `text-in-file`：读取 `payload` 指定的数据文件，若报文字段包含文件中的任意一行，则匹配成功。
  - `multi-text`：`payload` 为一个空格分割的字符串列表，若报文字段包含列表中的任意一个字符串，则匹配成功。
- `action`：字符串，表示匹配成功后的动作，目前支持：
  - `deny`：拒绝请求。
  - `pass`：放行请求。
- `placeholders`：字符串或字符串列表，表示要参与匹配的报文字段类型。目前支持：
  - `URLPath`：URL 中 `:path` 部分（不包含查询字符串）。
  - `URLFilename`：`URLPath` 按 `/` 分割的最后一个分量。
  - `URLBasename`：`URLFilename` 去除文件扩展名的部分。
  - `URLParamName`：URL 中查询字符串的字段名。
  - `URLParamValue`：URL 中查询字符串的字段值。其中，又有：
    - `URLParamValue:XXXXX`：URL 查询字符串中，字段 `XXXXX` 的字段值。
    - `!URLParamValue:XXXXX`：URL 查询字符串中，除了字段 `XXXXX`，其他字段的值。
  - `HeaderName`：请求头的名称。
  - `HeaderValue`：请求头的值。支持和 `URLParamValue` 相同的语法。例如，`HeaderValue:User-Agent` 表示只匹配 `User-Agent` 请求头的值。
  - `HTMLFormName`：`application/x-www-form-urlencoded` 类型请求体中的表单字段名。
  - `HTMLFormValue`：`application/x-www-form-urlencoded` 类型请求体中的表单字段值。支持和 `URLParamValue` 相同的语法。
  - `RawBody`：请求体的原始内容。
- `transformations`：字符串或字符串列表，表示在进行匹配前要对报文字段执行的转换操作。目前版本支持：
  - `Plain`：不进行任何转换。
  - `Base64`：对字段内容进行 Base64 解码。
  - `URL`：对字段内容进行 URL 解码。
  - 多个基础转换的组合，例如 `Base64|URL` 表示先对字段内容进行 Base64 解码，再对解码后的内容进行 URL 解码。
- `tags`：字符串或字符串列表，表示规则的标签，是可选字段。

为了使用 YAML 规则文件，需要先将它们转换为 C++ 源码文件，这个工作由脚本 `gen_cpp_rules_v1.py` 实现。为了使用该脚本，需要安装依赖：

```shell
pip install openapi_schema_validator
```

使用脚本时，需要指定包含 YAML 规则文件和数据文件的目录，并且该目录下必须包含一个 `rule_schema.yaml` 文件，它是规则文件的 JSON Schema 描述，用于检查规则文件的正确性。运行脚本：

```shell
python3 ./python/gen_cpp_rules_v1.py ./rules
```

如果规则文件都是有效的，上述命令会生成 `static_rules.cc` 文件，它将被用于插件的编译。

## 插件配置

本插件支持灵活的规则过滤操作，这是由插件配置实现的。一个有效的插件配置示例如下：

```json
{
  "rule_server": "rule_server",
  "enabled_rules": {
    "filename": [
      "**/*.yaml",
      "**/*.yml"
    ],
    "transformations" : [
      "Plain",
      "URL"
    ]
  },
  "disabled_rules": [
    {
      "id_max": 932300,
      "filename": "crs-selection/REQUEST-932-APPLICATION-ATTACK-RCE.yaml"
    },
    {
      "placeholders" : "*Header*",
      "tags": [
        "test",
        "not valid"
      ]
    }
  ]
}
```

插件配置由三个字段组成：`rule_server` 表示规则服务器的地址，`enabled_rules` 表示启用规则的过滤条件，`disabled_rules` 表示禁用规则的过滤条件。

使用规则服务器还需要在 `envoy.yaml` 中设置规则服务器信息：

```yaml
static_resources:
  ...
  clusters:
  ...
  - name: rule_server
    connect_timeout: 30s
    type: STATIC
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: rule_server
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 11111
```

`enabled_rules` 和 `disabled_rules` 可以是一个字典，也可以是一个字典的列表。我们把一个字典称为一个过滤条件。一个过滤条件下可以包含多个过滤子条件，它们是 AND 的关系。列表中的多个过滤条件是 OR 的关系。

过滤子条件可以是任意一个规则的字段，以及额外支持的 `filename`, `id_min`，`id_max`。这些过滤子条件的大致可以分为：

- `id_min`, `id_max`：分别指定规则 ID 的下限和上限。
- `filename`：YAML 文件相对路径，支持 `*` 通配符和 `**` 的多层目录匹配。
- `placeholders`, `transformations`：这两个比较特殊，因为它们不对整条规则进行否定。例如，出现在 `enabled_rules` 中的 `placeholders` 为 `URLPath`，它表示规则只检查 `URLPath` 字段，其他报文字段不做检查，而不是不采用所有包含 `URLPath` 的规则。
- `id`, `matchType`, `action`, `tags`：对不满足条件的整条规则进行否定。

除了 `id`, `id_min`, `id_max`, 其他过滤子条件都支持 `*` 通配符。

## 在线更新配置和规则

本插件支持对运行中的插件进行配置更新和规则更新。插件有两种在线更新方式：

- 定时发起对 `rule_server` 的请求，获取最新的配置和规则。
- 通过特殊的 HTTP 请求上传新的配置和规则。

第一种方式更为安全和自然，更为推荐使用。

首先，我们要安装脚本的依赖：

```shell
pip install jsonschema protobuf openapi_schema_validator
```

下面分别介绍两种更新方式的具体方法。

### 插件定时请求 `rule_server` 更新配置和规则

启动配置服务器，进行**配置**更新：

```shell
python3 ./python/config_server_v1.py 127.0.0.1:11111 ./config/config_schema.json ./config/plugin_config.json
```

其中，`127.0.0.1:11111` 是启动的服务器的地址，`./config/config_schema.json` 是用于检查插件配置正确性的 JSON Schema 描述，`./config/plugin_config.json` 是要更新为的插件配置文件。

启动规则服务器，进行**规则**更新：

```shell
python3 ./python/rule_server_v1.py 127.0.0.1:11111 ./rules
```

其中，`rules` 是包含 YAML 规则文件、数据文件以及 `rule_schema.yaml` 的目录。

注意，**当前版本此方法还不可用**。我之前调试出过一个可用版本，但是重装系统丢了，现在改不好了。猜想仍然是 `httpCall` 的报文头字段设置有问题。

### 通过 HTTP 请求更新配置和规则

通过 HTTP 请求进行**配置**更新：

```shell
python3 ./python/config_client_v1.py 127.0.0.1:10000 ./config/config_schema.json ./config/plugin_config.json
```

其中，`127.0.0.1:10000` 是插件的地址，`./config/config_schema.json` 是用于检查插件配置正确性的 JSON Schema 描述，`./config/plugin_config.json` 是要更新为的插件配置文件。

通过 HTTP 请求进行**配置**更新：

```shell
python3 ./python/rule_client_v1.py 127.0.0.1:10000 ./rules
```

其中，`rules` 是包含 YAML 规则文件、数据文件以及 `rule_schema.yaml` 的目录。

注意，两个脚本只会向插件发送一个 HTTP 请求，因此，更新了配置或规则的 VM 只有一个。如果要把所有 VM 都更新，可能需要多次调用脚本或把它修改为多次发起 HTTP 请求。因此无论是从安全性还是易用性考虑，都推荐使用前一种方法。
