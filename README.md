# JSON Merge, Patch, Diff, Validate, Canonicalize & Redact Service

一个基于 FastAPI 的 JSON 处理服务，提供六个接口：

- `POST /merge`：接收 `base`、`left`、`right` 三个 JSON 文档，将 left 和 right
  各自相对 base 的修改做三方合并；存在冲突时返回 `409` 并按 JSON Pointer 列出
  全部冲突。
- `POST /patch`：接收 `document` 与 `operations`，按数组顺序在**深拷贝**上原子
  执行 [RFC 6902](https://www.rfc-editor.org/rfc/rfc6902) JSON Patch 的
  `add`、`remove`、`replace`、`test` 操作。
- `POST /diff`：接收任意 JSON 值 `source` 与 `target`，返回把 source 变为
  target 所需的 RFC 6902 `operations`，可直接原样交给 `/patch`；对象按成员递归
  比较，数组按最长公共子序列对齐，公共位置继续递归而非整段替换。
- `POST /validate`：接收 JSON Schema `schema` 与任意 JSON `document`，按
  [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/json-schema-core)
  校验；仅允许 schema 内 `#` 本地引用，远程/无法解析的引用或无效 schema 返回
  `422`，合法 schema 一律返回 `200` 并在失败时列出全部叶子错误。
- `POST /canonicalize`：接收任意 JSON `document`，按
  [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)（JCS）生成无空白、确定性的
  规范 JSON 文本，并返回其 SHA-256 摘要。
- `POST /redact`：接收 `document` 与按顺序声明的 `rules`，用 JSON Pointer
  glob（`*` 匹配单层、`**` 匹配任意深度，数组索引同样支持 `*`）定位字段，执行
  `remove`（删除）、`mask`（整体替换为 `"***"`）与 `hash`（替换为该值的
  SHA-256）三种脱敏动作。全部规则先校验再执行；多规则命中同一路径时按
  「通配符更少 → 模式更长 → 声明更早」裁决；返回脱敏文档与每个命中的
  RFC 6901 路径，且绝不修改输入。

## 快速开始

一条命令启动（依赖随镜像构建自动安装）：

```bash
docker compose up --build
```

服务地址：http://localhost:8000 （交互式文档：http://localhost:8000/docs）

本地开发（不用 Docker）：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API

### `POST /merge`

请求体为三个任意 JSON 值（对象、数组、标量均可）：

```json
{
  "base":  { "a": 1, "b": [1, 2] },
  "left":  { "a": 2, "b": [1, 2] },
  "right": { "a": 1, "b": [1, 2, 3] }
}
```

**合并成功 → `200`**，返回合并结果：

```json
{ "merged": { "a": 2, "b": [1, 2, 3] } }
```

**合并冲突 → `409`**，返回按 JSON Pointer（RFC 6901）排序的冲突列表：

```json
{
  "detail": "merge conflict",
  "conflicts": [
    {
      "path": "/a",
      "base":  { "present": true,  "value": 1 },
      "left":  { "present": false, "value": null },
      "right": { "present": true,  "value": 2 }
    }
  ]
}
```

每个冲突包含：

| 字段    | 说明                                                         |
| ------- | ------------------------------------------------------------ |
| `path`  | 冲突位置的 JSON Pointer（根冲突为空字符串 `""`）             |
| `base`  | base 在该路径的值                                            |
| `left`  | left 在该路径的值                                            |
| `right` | right 在该路径的值                                           |

每一侧用 `{"present": bool, "value": ...}` 表示，以此**区分键缺失与 null**：
键不存在时 `present: false`（`value` 固定为 `null`）；键存在且值为 JSON `null`
时 `present: true, value: null`。

### `POST /patch`

请求体：

| 字段         | 类型    | 说明                                   |
| ------------ | ------- | -------------------------------------- |
| `document`   | 任意 JSON | 待打补丁的文档                        |
| `operations` | 数组    | 按顺序执行的 RFC 6902 操作             |

```json
{
  "document": { "a": [1, 2], "b": 3 },
  "operations": [
    { "op": "test",    "path": "/b",     "value": 3 },
    { "op": "add",     "path": "/a/-",   "value": 3 },
    { "op": "replace", "path": "/b",     "value": 30 },
    { "op": "add",     "path": "/c",     "value": "new" }
  ]
}
```

**全部成功 → `200`**，返回最终文档：

```json
{ "document": { "a": [1, 2, 3], "b": 30, "c": "new" } }
```

操作在 `document` 的**深拷贝**上执行，原请求文档不会被修改；失败时也绝不返回
部分结果。

#### 操作语义

| op        | `value` | 语义                                                         |
| --------- | ------- | ------------------------------------------------------------ |
| `add`     | 必须    | 对象：新增键，键已存在则等价于 `replace`；数组：在索引前插入，末级 token 为 `-` 时追加；根路径：替换整个文档 |
| `remove`  | 禁止    | 删除对象键或数组元素（数组后续元素前移）；不得指向根路径     |
| `replace` | 必须    | 替换**已存在**的目标；根路径替换整个文档                     |
| `test`    | 必须    | 断言目标值与 `value` JSON 相等，不等则失败                   |

- `add` 的数组索引允许等于当前长度（效果同追加）；`replace`/`remove`/`test`
  的目标必须已存在，索引必须在 `[0, length)` 内。
- 只有 `add` 可以使用 `-`（追加标记），其他操作携带 `-` 一律视为请求非法。
- `test` 的相等性沿用合并接口的规则：`1` 与 `1.0` 相等，`true` 与 `1` 不等，
  数组/对象递归比较。

**路径不存在、数组越界或 test 失败 → `409`**：

```json
{
  "detail": "patch conflict",
  "failed_index": 2,
  "path": "/b",
  "reason": "test failed: target value differs from 'value'"
}
```

| 字段           | 说明                                           |
| -------------- | ---------------------------------------------- |
| `failed_index` | 失败操作在 `operations` 中的下标（从 0 开始） |
| `path`         | 失败操作的 JSON Pointer                        |
| `reason`       | 失败原因                                       |

**指针语法或操作结构非法 → `422`**（同样带 `failed_index` / `path` /
`reason`；错误在任何操作执行前检出）：

- 缺少 `op` / `path`，或 `op` 不在支持列表内；
- `add`/`replace`/`test` 缺少 `value`，或 `remove` 携带 `value`；
- JSON Pointer 非空且不以 `/` 开头、`~` 后不是 `0`/`1`；
- 数组位置的 token 不是数字、带前导零（`/01`），或非 `add` 操作使用 `-`。

```json
{
  "detail": "invalid patch operation",
  "reason": "'remove' must not carry a 'value' field",
  "failed_index": 1,
  "path": "/a"
}
```

#### JSON Pointer 转义

路径按 RFC 6901 以 `/` 分隔；键名中的特殊字符用 `~1` 表示 `/`、`~0` 表示
`~`（先解 `~1` 再解 `~0`）。空字符串 `""` 指向整个文档。例如键 `a/b`写作
`/a~1b`，键 `~x` 写作 `/~0x`。

### `POST /diff`

请求体含两个**任意 JSON 值**（对象、数组、标量、甚至根级别的 `null` 均可）：

| 字段     | 类型    | 说明                       |
| -------- | ------- | -------------------------- |
| `source` | 任意 JSON | 原始值                    |
| `target` | 任意 JSON | 目标值                    |

**成功 → `200`**，返回 `operations`，即把 `source` 逐条变成 `target` 的
RFC 6902 操作列表，**可直接原样作为 `/patch` 的 `operations`**：

```json
{
  "operations": [
    { "op": "add",     "path": "/a/-",   "value": 4 },
    { "op": "replace", "path": "/b/x",   "value": 2 },
    { "op": "add",     "path": "/b/y",   "value": 3 },
    { "op": "remove",  "path": "/gone" },
    { "op": "add",     "path": "/new",   "value": "v" }
  ]
}
```

与 `/patch` 串联：

```bash
curl -s -X POST http://localhost:8000/diff \
  -H 'Content-Type: application/json' \
  -d '{"source":{"a":[1,2],"b":1},"target":{"a":[1,2,3],"b":2}}'
# => {"operations":[{"op":"add","path":"/a/-","value":3},
#                   {"op":"replace","path":"/b","value":2}]}
```

差异生成规则：

| 情形                                   | 生成的操作                                                                 |
| -------------------------------------- | -------------------------------------------------------------------------- |
| source 与 target 结构相等              | `[]`（`1` 与 `1.0` 视为相等，`true` 与 `1` 不等）                          |
| 对象共有成员且值不同                   | 按成员**递归**比较，只生成最小操作；对象成员按 Unicode 码点序处理（确定性） |
| 对象 target 多出/少掉的成员            | `add` / `remove`（`add` 到已存在成员时与 `replace` 等价）                  |
| 数组                                   | 以 JSON 相等计算**最长公共子序列（LCS）**：公共位置保留并继续递归，多出来的 source 元素按高索引优先 `remove`，多出来的 target 元素在锚点前逆序 `add`（末尾用 `/-` 追加） |
| 锚点之间同偏移的一对一异值元素         | 递归比较；叶子差异为单条 `replace`，而非一条 `remove` + 一条 `add`          |
| 类型变化（对象↔数组↔标量）或标量变化   | 单条 `replace`                                                             |
| 根级整体变化                           | 根指针 `""` 上的 `replace`（`/patch` 支持替换整个文档）                    |

关键点：

- **JSON Pointer 正确转义**：成员名中的 `~` 写作 `~0`、`/` 写作 `~1`
  （如成员 `a/b` → `/a~1b`，成员 `~x` → `/~0x`），数组位置仍为数字索引。
- **操作顺序保证可直接应用**：数组删除总是高索引先执行、插入在锚点前逆序执行，
  因此前面的操作不会让后续路径失效；把返回的 `operations` 逐条交给 `/patch`，
  结果**恰好**等于 `target`。
- **避免整段替换**：数组中大部分元素相同、仅个别增删改时，不会替换整个数组；
  公共位置的对象/数组还会继续向下递归。
- **结果确定性**：相同输入永远返回字节相同的操作列表（成员按码点序、LCS 回溯
  平局时优先跳过 source 元素）。
- 不修改请求中的 `source`/`target`；操作里的 `value` 在 `/patch` 中还会再做一次
  深拷贝。

```bash
# 数组小改：保留公共元素、公共位置递归，而不是整段替换
curl -s -X POST http://localhost:8000/diff \
  -H 'Content-Type: application/json' \
  -d '{"source":[{"id":1,"v":0},{"id":2}],"target":[{"id":1,"v":1},{"id":2},{"id":3}]}'
# => {"operations":[{"op":"replace","path":"/0/v","value":1},
#                   {"op":"add","path":"/-","value":{"id":3}}]}

# 相同输入 → 空数组
curl -s -X POST http://localhost:8000/diff \
  -H 'Content-Type: application/json' \
  -d '{"source":{"a":[1,2]},"target":{"a":[1,2]}}'
# => {"operations":[]}

# 类型变化 → replace
curl -s -X POST http://localhost:8000/diff \
  -H 'Content-Type: application/json' \
  -d '{"source":{"a":1},"target":{"a":[1]}}'
# => {"operations":[{"op":"replace","path":"/a","value":[1]}]}
```

**缺少 `source` 或 `target` 字段、或请求体无法解析为 JSON → `422`**。

### `POST /validate`

请求体含两个字段：

| 字段       | 类型      | 说明                                        |
| ---------- | --------- | ------------------------------------------- |
| `schema`   | 任意 JSON | JSON Schema Draft 2020-12（对象或布尔值）   |
| `document` | 任意 JSON | 待校验文档                                  |

```json
{
  "schema": {
    "$defs": { "name": { "type": "string", "minLength": 1 } },
    "type": "object",
    "required": ["first"],
    "properties": {
      "first": { "$ref": "#/$defs/name" },
      "tags": { "items": { "type": "string" } }
    }
  },
  "document": { "first": "", "tags": ["a", 3] }
}
```

**schema 合法时一律 `200`**（无论文档是否通过），返回 `valid` 与错误列表：

```json
{
  "valid": false,
  "errors": [
    {
      "instance_path": "/first",
      "schema_path": "/properties/first/minLength",
      "keyword": "minLength",
      "message": "'' should be non-empty"
    },
    {
      "instance_path": "/tags/1",
      "schema_path": "/properties/tags/items/type",
      "keyword": "type",
      "message": "3 is not of type 'string'"
    }
  ]
}
```

通过时为 `{"valid": true, "errors": []}`。每个错误包含：

| 字段            | 说明                                                              |
| --------------- | ----------------------------------------------------------------- |
| `instance_path` | 文档中失败位置的 RFC 6901 JSON Pointer（根为 `""`）               |
| `schema_path`   | schema 中触发断言位置的 RFC 6901 JSON Pointer（`$ref` 解析到目标）|
| `keyword`       | 失败关键字，如 `type`、`required`、`oneOf`（布尔 schema 时为 `""`）|
| `message`       | 校验器给出的失败原因                                              |

- 列出**全部叶子错误**：`oneOf` / `anyOf` 等聚合关键字会展开到各分支的叶子；
  路径、关键字、消息完全相同的叶子只保留一条。
- 稳定排序：先按 `instance_path`（数组索引按数值且排在成员名前，成员名按
  Unicode 码点），再按 `keyword`、`schema_path`、`message`。
- `$ref` / `$dynamicRef` **只允许文档内 `#` 引用**：`#/$defs/name`、
  `#anchor`（配合 `$id`）均可；`https://…` 等远程 URI、`other.json#…` 等跨
  文档相对引用一律拒绝。解析器也被配置为绝不发起任何网络请求。
- 即使文档本身恰好“匹配”，无效 schema 仍返回 `422`；`enum`、`default`、
  `examples` 等注解内长得像 `$ref` 的数据不会被误判。

**远程引用、无法解析的本地引用或无效 schema → `422`**：

```json
{
  "detail": "invalid schema",
  "reason": "unresolvable reference",
  "ref": "#/$defs/missing",
  "message": "local reference '#/$defs/missing' cannot be resolved: ..."
}
```

`reason` 取值：

| 值                       | 场景                                                |
| ------------------------ | --------------------------------------------------- |
| `remote reference`       | 引用未以 `#` 开头（远程 URI / 跨文档相对引用 / 空值）|
| `unresolvable reference` | `#` 引用的指针或锚点在 schema 内不存在，或纯自引用循环 |
| `invalid schema`         | schema 不是对象/布尔值，或不符合 Draft 2020-12 元 schema |

### `POST /canonicalize`

请求体只含一个字段，`document` 可以是**任意 JSON 值**（对象、数组、标量、甚至
根级别的 `null`/数字/字符串）：

```json
{ "document": { "b": 1, "a": [null, true, 1000000000000000000000], "€": 4.5 } }
```

**成功 → `200`**，返回规范文本及其 SHA-256（对规范文本的 UTF-8 字节取摘要）：

```json
{
  "canonical": "{\"a\":[null,true,1e+21],\"b\":1,\"€\":4.5}",
  "sha256": "aa1895e4836931e94f127911ca20cbf5ec60684dbf980edd11b91ba0a98dd7e9"
}
```

规范化严格遵循 RFC 8785（JSON Canonicalization Scheme）：

| 规则       | 说明                                                                                                                              |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------- |
| 空白       | 不输出任何空白字符，单行输出                                                                                                      |
| 对象键排序 | 递归排序；键名按 **UTF-16 码元**（无符号 16 位整数）逐码元比较，空串/前缀短者排前；与 Unicode 码点序在辅助平面字符上不同          |
| 数组       | 元素顺序保持不变（但其中嵌套对象仍会排序）                                                                                        |
| 数字       | ECMAScript `Number.prototypeToString`（最短往返）表示：`-0` 输出 `0`；`1e21` 输出 `1e+21`，`1e20` 仍为定长；指数不补零（`5e-324`） |
| 字符串     | 仅做必要转义：`"` → `\"`、`\` → `\\`、控制字符用 `\b \t \n \f \r` 或小写 `\uhhhh`；`/`、`'`、非 ASCII（如 `€`、emoji）原样输出 UTF-8 |
| 布尔/null  | 输出 `true` / `false` / `null`，且 `true` 不等同于 `1`                                                                            |

同一份文档（无论原始键序、空白或数字写法如何）必然得到**字节完全相同**的规范
文本和 SHA-256，可直接用于签名、去重与完整性校验。

**缺少 `document` 字段或请求体无法解析为 JSON → `422`**；文档能解析但包含
JCS 不允许的值（如超出 IEEE 754 double 范围的整数）同样返回 `422`：

```json
{ "detail": "document cannot be canonicalized", "reason": "..." }
```

### `POST /redact`

请求体含两个字段：

| 字段       | 类型      | 说明                                                          |
| ---------- | --------- | ------------------------------------------------------------- |
| `document` | 任意 JSON | 待脱敏文档                                                    |
| `rules`    | 数组      | 按顺序声明的脱敏规则，每条为 `{"path": ..., "action": ...}`   |

规则路径是带 glob 扩展的 [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901)
JSON Pointer，支持 `~0` / `~1` 转义：

| 通配符          | 语义                                                                                              |
| --------------- | ------------------------------------------------------------------------------------------------- |
| `*`（整段）     | 恰好匹配**一层**：对象的每个成员或数组的每个元素；数组位置也可写 `*`                              |
| `**`（整段）    | 匹配**零层或任意多层**：`/a/**/b` 同时命中 `/a/b`、`/a/x/b`、`/a/x/y/b`；`/**` 还命中文档根节点 |
| 其它 token      | 字面量；token 中间出现的 `*`（如 `/a*b`）只是普通字符，不是通配符                                 |

动作：

| action   | 语义                                                                                                |
| -------- | --------------------------------------------------------------------------------------------------- |
| `remove` | 删除命中节点（删对象成员或数组元素，数组后续元素前移）；不得删除整个文档（根命中时返回 `409`）      |
| `mask`   | 把命中节点**整体**替换为字符串 `"***"`（对象、数组子树也一次性替换）                                |
| `hash`   | 替换为命中值的 SHA-256 十六进制摘要：先按 [RFC 8785](#post-canonicalize) 规范化再对 UTF-8 字节取摘要 |

```json
{
  "document": {
    "user": {
      "name": "Alice",
      "ssn": "123-45-6789",
      "cards": [
        { "no": "4111-1111", "cvv": "111" },
        { "no": "4222-2222", "cvv": "222" }
      ]
    },
    "meta": { "deep": { "secret": 7 } },
    "public": true
  },
  "rules": [
    { "path": "/user/ssn",          "action": "remove" },
    { "path": "/user/cards/*/cvv",  "action": "mask"   },
    { "path": "/**/secret",         "action": "hash"   },
    { "path": "/**/no",             "action": "mask"   }
  ]
}
```

**成功 → `200`**，返回脱敏后的文档 `document` 与命中列表 `hits`（按 RFC 6901
路径稳定排序；同一父级下数组索引按数值且排在成员名之前）。每个命中包含路径
`path`、实际执行的动作 `action` 以及获胜规则在 `rules` 中的下标 `rule`：

```json
{
  "document": {
    "user": {
      "name": "Alice",
      "cards": [
        { "no": "***", "cvv": "***" },
        { "no": "***", "cvv": "***" }
      ]
    },
    "meta": { "deep": { "secret": "7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451" } },
    "public": true
  },
  "hits": [
    { "path": "/meta/deep/secret",    "action": "hash",   "rule": 2 },
    { "path": "/user/cards/0/cvv",    "action": "mask",   "rule": 1 },
    { "path": "/user/cards/0/no",     "action": "mask",   "rule": 3 },
    { "path": "/user/cards/1/cvv",    "action": "mask",   "rule": 1 },
    { "path": "/user/cards/1/no",     "action": "mask",   "rule": 3 },
    { "path": "/user/ssn",            "action": "remove", "rule": 0 }
  ]
}
```

**多规则裁决**：先把所有模式匹配到的具体路径求出来；同一条具体路径被多条规则
命中时，按以下顺序选出唯一的获胜规则：

1. **通配符更少**：`*` 与 `**` 各计一个通配符（字面路径计 0，永远最优先）；
2. **模式更长**：通配符数量相同时，token 数更多的 glob 获胜（如
   `/a/*/x/c` 胜 `/**/c`）；
3. **声明顺序**：前两项都相同（如 `/a/*/c` 与 `/a/**/c`）时，`rules` 中
   更早声明的获胜。

其余规则要点：

- **动作是终止性的**：祖先节点被某条规则 `remove`/`mask`/`hash` 后，其子树不再
  存在，命中子树内部的规则不会执行、也不会出现在 `hits` 中（避免报告不存在的
  路径）。各具体路径的获胜规则彼此独立：glob 在浅层输给精确路径后，深层只有它
  能到达的节点仍会继续生效。
- **全部规则先校验**：任何一条规则非法都会在接触文档前返回 `422`，绝不会出现
  部分脱敏；校验与执行都在重建出的新结构上进行，**输入 `document` 不被修改**，
  返回结果也不与输入共享子树。
- 空指针 `""` 指向整个文档；`mask`/`hash` 根节点会把整个文档替换成一个字符串，
  而 `remove` 根节点（含 `/**` 命中根）无法执行 → `409`。
- 规则对象的额外字段会被忽略；未命中任何节点的规则不产生命中（`hits` 为空时
  文档原样返回）。

**规则非法 → `422`**（与 `/patch` 一致，带 `failed_index` / `path` /
`reason`）：

- `rules` 不是数组，或某条规则不是对象；
- 缺少 `path` / `action`，或 `action` 不在 `remove`、`mask`、`hash` 中；
- `path` 不是字符串、非空但不以 `/` 开头，或 `~` 后不是 `0`/`1`。

```json
{
  "detail": "invalid redaction rule",
  "reason": "malformed JSON Pointer: non-empty pointer must start with '/'",
  "failed_index": 0,
  "path": "a"
}
```

**规则合法但无法应用 → `409`**：目前唯一的情形是 `remove` 命中整个文档。

```json
{
  "detail": "redaction conflict",
  "failed_index": 0,
  "path": "",
  "reason": "'remove' cannot target the whole document"
}
```

### `GET /health`

健康检查，返回 `{"status": "ok"}`。

## 合并规则

1. **两侧相同**（包括都未修改、都删除、做了相同修改）→ 取该值。
2. **仅一侧修改** → 取修改后的值（删除即移除该键）。
3. **两侧修改不同**：
   - 三者（或两侧新增时）都是对象 → 按键递归合并；
   - 否则（同路径异值、类型变化、数组两侧改得不同）→ 冲突，返回 `409`。
4. **一侧删除、另一侧修改其内部后代** → 冲突，返回 `409`。
5. **数组整体比较**：不做逐元素合并；仅一侧改了数组则取该侧，两侧改成不同
   数组则整个数组作为一个冲突上报。

## 示例

```bash
# 合并成功
curl -s -X POST http://localhost:8000/merge \
  -H 'Content-Type: application/json' \
  -d '{"base":{"a":1},"left":{"a":2},"right":{"a":1}}'
# => {"merged":{"a":2}}

# 冲突：left 删除了 /a，right 修改了 /a 的后代
curl -s -X POST http://localhost:8000/merge \
  -H 'Content-Type: application/json' \
  -d '{"base":{"a":{"x":1}},"left":{},"right":{"a":{"x":2}}}'
# => 409 {"detail":"merge conflict","conflicts":[{"path":"/a", ...}]}

# JSON Patch：数组追加 + 断言 + 替换
curl -s -X POST http://localhost:8000/patch \
  -H 'Content-Type: application/json' \
  -d '{"document":{"a":[1],"b":3},"operations":[{"op":"add","path":"/a/-","value":2},{"op":"test","path":"/b","value":3}]}'
# => {"document":{"a":[1,2],"b":3}}

# test 失败 → 409（无部分结果）
curl -s -X POST http://localhost:8000/patch \
  -H 'Content-Type: application/json' \
  -d '{"document":{"a":1},"operations":[{"op":"add","path":"/b","value":2},{"op":"test","path":"/a","value":99}]}'
# => 409 {"detail":"patch conflict","failed_index":1,"path":"/a","reason":"test failed: ..."}

# 生成 diff（返回的 operations 可直接交给 /patch）
curl -s -X POST http://localhost:8000/diff \
  -H 'Content-Type: application/json' \
  -d '{"source":{"a":[1,2,3],"b":1},"target":{"a":[1,2,3,4],"b":2}}'
# => {"operations":[{"op":"add","path":"/a/-","value":4},{"op":"replace","path":"/b","value":2}]}

# diff 数组：LCS 对齐，公共位置递归，不整段替换
curl -s -X POST http://localhost:8000/diff \
  -H 'Content-Type: application/json' \
  -d '{"source":[1,2,3],"target":[1,9,3]}'
# => {"operations":[{"op":"replace","path":"/1","value":9}]}

# RFC 8785 规范化（键排序 + 确定性数字 + 仅必要转义）
curl -s -X POST http://localhost:8000/canonicalize \
  -H 'Content-Type: application/json' \
  -d '{"document":{"z":1,"a":["€\n",null,false],"n":1e21}}'
# => {"canonical":"{\"a\":[\"€\\n\",null,false],\"n\":1e+21,\"z\":1}","sha256":"c5b1bd7f8dc067ea4a691fdc8edf37c90e4bf05234918d943d9b3d9ee993b061"}

# 缺少 document 字段 → 422
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8000/canonicalize \
  -H 'Content-Type: application/json' -d '{}'
# => 422

# JSON Schema 校验：合法 schema、文档不合规 → 200 valid=false
curl -s -X POST http://localhost:8000/validate \
  -H 'Content-Type: application/json' \
  -d '{"schema":{"type":"array","items":{"type":"integer"}},"document":[1,"x",3]}'
# => {"valid":false,"errors":[{"instance_path":"/1","schema_path":"/items/type", ...}]}

# 远程引用 → 422（不发起任何网络请求）
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8000/validate \
  -H 'Content-Type: application/json' \
  -d '{"schema":{"$ref":"https://example.com/s"},"document":{}}'
# => 422

# 无法解析的本地引用 → 422
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8000/validate \
  -H 'Content-Type: application/json' \
  -d '{"schema":{"$ref":"#/$defs/nope"},"document":{}}'
# => 422

# 数据脱敏：删除精确路径、单层 * 批量遮蔽、** 任意深度哈希
curl -s -X POST http://localhost:8000/redact \
  -H 'Content-Type: application/json' \
  -d '{"document":{"user":{"ssn":"1","cards":[{"cvv":"11"},{"cvv":"22"}]},"x":{"secret":5}},
       "rules":[{"path":"/user/ssn","action":"remove"},
                {"path":"/user/cards/*/cvv","action":"mask"},
                {"path":"/**/secret","action":"hash"}]}'
# => {"document":{"user":{"cards":[{"cvv":"***"},{"cvv":"***"}]},"x":{"secret":"..."}},
#     "hits":[{"path":"/user/cards/0/cvv","action":"mask","rule":1}, ...]}

# 删除整个文档 → 409
curl -s -w '\n%{http_code}\n' -X POST http://localhost:8000/redact \
  -H 'Content-Type: application/json' \
  -d '{"document":{"a":1},"rules":[{"path":"","action":"remove"}]}'
# => {"detail":"redaction conflict",...,"path":"","reason":"'remove' cannot target the whole document"}
# => 409

# 非法规则（所有规则先校验，绝不部分执行）→ 422
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8000/redact \
  -H 'Content-Type: application/json' \
  -d '{"document":{"a":1},"rules":[{"path":"a","action":"remove"}]}'
# => 422
```

## 测试

```bash
pip install -r requirements-dev.txt
pytest
```

## 项目结构

```
app/main.py           # FastAPI 应用：/merge、/patch、/diff、/validate、/canonicalize 与 /redact 入口
app/patch.py          # RFC 6902 JSON Patch 校验与原子执行
app/diff.py           # RFC 6902 diff 生成：对象递归比较、数组 LCS 对齐
app/validate.py       # JSON Schema Draft 2020-12 校验、仅本地 # 引用与叶子错误收集
app/canonicalize.py   # RFC 8785 JCS 规范化序列化（UTF-16 键序、ECMAScript 数字）
app/redact.py         # JSON Pointer glob（* / **）规则匹配、优先级裁决与 remove/mask/hash
app/jsonutil.py       # JSON 相等性、MISSING 哨兵与 RFC 6901 转义（接口共用）
tests/test_merge.py        # /merge 测试
tests/test_patch.py        # /patch 测试
tests/test_diff.py         # /diff 测试（含 diff→/patch 随机往返）
tests/test_validate.py     # /validate 测试
tests/test_canonicalize.py # /canonicalize 测试
tests/test_redact.py       # /redact 测试（glob、优先级裁决、422/409、不可变性）
requirements.txt     # 运行依赖（Docker 构建时自动安装）
requirements-dev.txt # 测试依赖
Dockerfile
docker-compose.yml
```
