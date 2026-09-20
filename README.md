# Firmware Image Assembly Service

FastAPI 服务：接收 Intel HEX 文本，逐行校验（字节数 + 二补校验和），按地址组装固件映像，
返回合并后的连续 Base64 段、段间空洞、入口地址与逐行诊断；并可针对一组命名内存区域
做布局校验（覆盖率、data/entry 权限、区域占用率）、规划整体重定位，对比当前/目标两个
映像规划 NOR Flash 的差分擦除/写入操作，并可对一组**给定的有序 erase/write 操作序列**
逐条回放 NOR Flash 状态、校验其合法性并确认最终映像与目标一致；还能按 Cortex-M 向量表
语义校验映像中的向量表
（初始栈顶、复位向量、Thumb 位与 ram/executable 区域归属），或将多个带唯一名称的
Intel HEX 映像按绝对地址叠加合并（同值归并并记录全部来源、冲突按连续段报告、入口一致性校验），
以及对组装后的整像计算**与记录分片/空洞表示无关的规范化内容指纹（SHA-256）**，
同时返回每段摘要、总字节数、入口地址与规范化清单；还可把组装后的映像**重新导出为
规范化 Intel HEX 文本**（按 `max_data_bytes` 确定性切分数据记录、任何记录不跨越
64 KiB 地址窗口、窗口切换时输出扩展线性地址记录、全部记录重算二补校验和、可选保留
入口地址），并返回导出的 HEX 文本与记录数。

## 快速启动（单条命令）

```bash
docker compose up --build
```

首次运行会构建镜像（安装 `requirements.txt` 中的 FastAPI/uvicorn 依赖）并启动服务；
前台运行时直接 `Ctrl-C` 停止。常用变体：

```bash
docker compose up --build -d      # 后台运行
docker compose logs -f            # 跟踪后台日志
docker compose down               # 停止并移除容器
docker compose up --build --force-recreate   # 改完代码后强制重建
```

服务监听容器内 **8000 端口**，compose 映射到宿主机同端口（`-p 8000:8000`，
可用 `localhost:8000` 或 `127.0.0.1:8000` 访问；换端口只需改映射左侧）。
例如改用宿主机 18000 端口：把 `docker-compose.yml` 中的 `"8000:8000"`
改成 `"18000:8000"`，或直接运行
`docker run --rm -p 18000:8000 hexasm`。
启动后访问：

- 接口文档（Swagger UI）：<http://localhost:8000/docs>
- 健康检查：<http://localhost:8000/health>

快速验证服务（指纹接口）：

```bash
curl -s -X POST http://localhost:8000/api/v1/image-digest \
  -H 'Content-Type: application/json' \
  -d '{"hex_text": ":10000000214601360121470136007EFE09D2190141\n:00000001FF\n"}' | jq .image_sha256
```

不使用 Compose 时：

```bash
docker build -t hexasm . && docker run --rm -p 8000:8000 hexasm
```

本地开发（无 Docker）：

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
pytest                 # 运行测试
```

## 接口

### `POST /api/v1/assemble`

JSON 请求体：

```json
{
  "hex_text": ":020000040800F2\n:10000000214601360121470136007EFE09D2190141\n:04000005080001C12D\n:00000001FF\n"
}
```

### `POST /api/v1/assemble/raw`

`text/plain` 请求体，直接粘贴 Intel HEX 文本：

```bash
curl -s -X POST http://localhost:8000/api/v1/assemble/raw \
  -H 'Content-Type: text/plain' \
  --data-binary @firmware.hex | jq
```

### 响应

无论 HEX 是否通过校验均返回 200，结果以 `ok` 与 `diagnostics` 判定：

```json
{
  "ok": true,
  "error_count": 0,
  "warning_count": 0,
  "entry_address": 134218177,
  "total_bytes": 16,
  "segment_count": 1,
  "segments": [
    {"start": 134217728, "end": 134217744, "size": 16, "data_base64": "IUYBNgEhRwE2AH7+CdIZAQ=="}
  ],
  "gaps": [],
  "diagnostics": [
    {"line": 1, "status": "ok", "record_type": "extended_linear_address",
     "address": 134217728, "byte_count": null, "message": "linear base set to 0x8000000"},
    {"line": 2, "status": "ok", "record_type": "data",
     "address": 134217728, "byte_count": 16, "message": "data: 16 byte(s) at 0x8000000"}
  ]
}
```

- `segments[]`：按地址升序合并的连续段，`data_base64` 为段内容，`end` 为开区间。
- `gaps[]`：相邻段之间的空洞（`start` 含、`end` 不含）。
- `entry_address`：最后一个 03/05 型记录给出的入口地址，无则为 `null`。
- `diagnostics[]`：逐行结果，`line` 从 1 开始，`0` 表示文件级问题（如缺失 EOF）。

### `POST /api/v1/validate-layout`

在组装结果之上做内存布局校验。请求体在 `hex_text` 之外增加 `regions`，
每个区域为半开区间 `[start, end)`：

```bash
curl -s -X POST http://localhost:8000/api/v1/validate-layout \
  -H 'Content-Type: application/json' \
  -d '{
    "hex_text": ":020000040800F2\n:10000000214601360121470136007EFE09D2190141\n:04000005080001C12D\n:00000001FF\n",
    "regions": [
      {"name": "flash",  "start": 134217728, "end": 134479872, "allow_data": true, "allow_entry": true},
      {"name": "config", "start": 134479872, "end": 134484992, "allow_data": true, "allow_entry": false}
    ]
  }' | jq
```

响应示例（同样恒为 200）：

```json
{
  "ok": true,
  "hex_ok": true,
  "regions_valid": true,
  "error_count": 0,
  "warning_count": 0,
  "entry_address": 134218177,
  "total_bytes": 16,
  "regions": [
    {
      "name": "flash", "start": 134217728, "end": 134479872, "size": 262144,
      "allow_data": true, "allow_entry": true,
      "occupied_bytes": 16, "utilization": 0.00006103515625, "violations": []
    },
    {
      "name": "config", "start": 134479872, "end": 134484992, "size": 5120,
      "allow_data": true, "allow_entry": false,
      "occupied_bytes": 0, "utilization": 0.0, "violations": []
    }
  ],
  "violations": [],
  "diagnostics": [ ... ]
}
```

判定规则：

- HEX 无效时只返回 `diagnostics`（`regions`/`violations` 为空、`regions_valid` 为 `null`），
  不执行布局判断。
- HEX 有效时先检查区域定义：每个区域须满足 `start < end`，且所有区域互不重叠
  （相邻边界相接允许）；定义不合法时 `regions_valid=false`，不再做字节级判定。
- 定义合法后，将固件连续段按区域边界切分，逐字节归属区域，并报告：
  - `uncovered_data`：未被任何区域覆盖的字节范围（`region` 为 `null`）；
  - `data_not_allowed`：落入 `allow_data=false` 区域的字节范围；
  - `entry_uncovered` / `entry_not_allowed`：入口地址（存在时）未落入任何区域，
    或落入 `allow_entry=false` 的区域。
- 每个区域汇总 `occupied_bytes`（落入的固件字节数）、`utilization`
  （`occupied_bytes / size`）及该区域关联的 `violations`；顶层 `violations`
  汇总全部违规。`ok` 仅在 HEX 有效且无任何违规时为 `true`。

### `POST /api/v1/plan-relocation`

固件整体重定位规划：对**所有固件段和入口地址施加同一个整数 `delta`**，
段内容与段间距离保持不变。在 `hex_text`、`regions` 之外可传 `max_abs_shift`
限制 `|delta|`。同样复用 HEX 解析与区域定义校验，任一无效即只返回诊断、
不做规划。

```bash
curl -s -X POST http://localhost:8000/api/v1/plan-relocation \
  -H 'Content-Type: application/json' \
  -d '{
    "hex_text": ":020000040800F2\n:10000000214601360121470136007EFE09D2190141\n:04000005080001C12D\n:00000001FF\n",
    "regions": [
      {"name": "flash", "start": 134283264, "end": 135266304, "allow_data": true, "allow_entry": true}
    ],
    "max_abs_shift": 1048576
  }' | jq
```

可行判定（全部为闭区间整数）：

- 每个固件段必须**完整落入**某个 `allow_data=true` 的区域（不允许跨区域边界）；
- 入口地址（存在时）必须落入某个 `allow_entry=true` 的区域；
- 搬移后所有地址必须仍为 32 位无符号地址（`0`..`0xFFFFFFFF`）；
- 给定 `max_abs_shift` 时还须满足 `|delta| <= max_abs_shift`。

响应在上述约束下求交集并合并出全部可行 delta 区间 `feasible_ranges`，
并选择 **`|delta|` 最小、绝对值相同再取数值较小（偏向负方向）** 的那个：

```json
{
  "ok": true,
  "hex_ok": true,
  "regions_valid": true,
  "error_count": 0,
  "warning_count": 0,
  "entry_address": 134218177,
  "total_bytes": 16,
  "max_abs_shift": 1048576,
  "feasible": true,
  "delta": 65536,
  "abs_shift": 65536,
  "feasible_ranges": [
    {"min_delta": 65536, "max_delta": 1048126}
  ],
  "relocated_entry_address": 134283713,
  "relocated_segments": [
    {"start": 134283264, "end": 134283280, "size": 16,
     "data_base64": "IUYBNgEhRwE2AH7+CdIZAQ=="}
  ],
  "violations": [],
  "diagnostics": [ ... ]
}
```

- `feasible`：是否存在满足全部约束的 delta；为 `false` 时
  `feasible_ranges` 为空，`delta`/`abs_shift` 为 `null`，
  且不返回 `relocated_segments`/`relocated_entry_address`。
- `feasible_ranges[]`：合并后的互不相交闭区间，`min_delta`/`max_delta`
  均含端点。
- `delta`：选中的统一搬移量；`relocated_segments[].data_base64` 为段内容，
  与 `/api/v1/assemble` 相同（搬移只改地址，不改字节）。
- HEX 无效（`hex_ok=false`、`regions_valid=null`）或区域定义不合法
  （`regions_valid=false`，`violations` 给出 `invalid_region`/
  `region_overlap`）时均不规划，`feasible=false`。
- 省略 `max_abs_shift` 时仅受区域与 32 位地址空间约束；对没有任何段与入口
  的空映像，可行集无界，返回 `delta=0` 与空的 `feasible_ranges`。

### `POST /api/v1/plan-flash-update`

Flash 差分烧写规划：复用 Intel HEX 解析器接收**当前映像 `current_hex`** 与
**目标映像 `target_hex`**，外加 Flash 窗口与粒度参数 `flash_start`、`flash_end`、
`erase_block_size`、`max_write_size`。任一 HEX 无效或参数不合法时只返回明确诊断、
**不生成任何操作**。

NOR Flash 语义：写只能把比特 `1 -> 0`，只有擦除整个块才能恢复 `0 -> 1`，擦除后
字节为 `0xFF`。两个映像中**未显式给出的地址一律按 `0xFF` 处理**。

```bash
curl -s -X POST http://localhost:8000/api/v1/plan-flash-update \
  -H 'Content-Type: application/json' \
  -d '{
    "current_hex": ":10000000000102030405060708090A0B0C0D0E0F78\n:00000001FF\n",
    "target_hex":  ":10000000FF0102030405060708090A0B0C0D0E0F79\n:00000001FF\n",
    "flash_start": 0,
    "flash_end": 256,
    "erase_block_size": 64,
    "max_write_size": 16
  }' | jq
```

判定与规划规则：

- 参数校验：`[flash_start, flash_end)` 必须是 32 位空间内非空半开区间，
  且 `flash_start`、`flash_end` **都必须对齐到 `erase_block_size`**；
  `erase_block_size`、`max_write_size` 必须为正整数；两个映像的所有数据字节
  必须完整落在 Flash 窗口内。不满足时 `params_valid=false`，`param_errors`
  给出 `invalid_flash_range` / `erase_block_unaligned` /
  `invalid_max_write_size` / `image_outside_flash`（含越界地址范围），不规划。
- 逐擦除块比较（块起始为按 `erase_block_size` 向下对齐的地址）：
  - 块内**任一字节发生 `0 -> 1`**（按位判断，例如 `0xFE -> 0xFF`）→
    先 `erase` 整块，再把目标映像中块内所有非 `0xFF` 字节重写（擦除把
    未变化字节也复位了，因此一并重写；目标即为 `0xFF` 的字节不写）；
  - 否则块无需擦除，**仅写实际发生变化的字节**（`1 -> 0` 与位变化均可直接写）。
- 所有待写字节先**合并为连续 run**（中间隔着不变字节则断开），再按
  `max_write_size` 切分；并且**任何 write 都不会跨越擦除块边界**
  （边界处即使地址连续也强制断开）。
- `operations` 按地址排序，同一块的 erase 排在其 write 之前；write 的
  `data_base64` 为待写目标字节，erase 的该字段为 `null`。

上例（当前首字节 `0x00` -> 目标 `0xFF`，触发擦除）响应：

```json
{
  "ok": true,
  "current_hex_ok": true,
  "target_hex_ok": true,
  "params_valid": true,
  "flash_start": 0,
  "flash_end": 256,
  "erase_block_size": 64,
  "max_write_size": 16,
  "error_count": 0,
  "warning_count": 0,
  "param_errors": [],
  "affected_blocks": [
    {
      "address": 0, "size": 64, "erase": true, "erase_size": 64,
      "write_bytes": 15, "changed_bytes": 1, "zero_to_one_bytes": 1
    }
  ],
  "operations": [
    {"kind": "erase", "address": 0, "end": 64, "size": 64, "block": 0,
     "data_base64": null},
    {"kind": "write", "address": 1, "end": 16, "size": 15, "block": 0,
     "data_base64": "AQIDBAUGBwgJCgsMDQ4P"}
  ],
  "affected_block_count": 1,
  "erase_count": 1,
  "erase_bytes": 64,
  "write_count": 1,
  "write_bytes": 15,
  "changed_bytes": 1,
  "zero_to_one_bytes": 1,
  "current_diagnostics": [ ... ],
  "target_diagnostics": [ ... ]
}
```

无需擦除的纯写入场景（多个不连续 run 分别合并，不变字节跳过）：

```json
{
  "ok": true,
  "current_hex_ok": true,
  "target_hex_ok": true,
  "params_valid": true,
  "affected_blocks": [
    {"address": 0, "size": 64, "erase": false, "erase_size": null,
     "write_bytes": 7, "changed_bytes": 7, "zero_to_one_bytes": 0}
  ],
  "operations": [
    {"kind": "write", "address": 16, "end": 20, "size": 4, "block": 0,
     "data_base64": "AAECAw=="},
    {"kind": "write", "address": 21, "end": 24, "size": 3, "block": 0,
     "data_base64": "BAUG"}
  ],
  "affected_block_count": 1,
  "erase_count": 0, "erase_bytes": 0,
  "write_count": 2, "write_bytes": 7,
  "changed_bytes": 7, "zero_to_one_bytes": 0
}
```

- `current_diagnostics` / `target_diagnostics`：两个 HEX 各自的逐行诊断；
  任一 HEX 无效时对应 `current_hex_ok`/`target_hex_ok` 为 `false`，
  `params_valid` 为 `null`，`operations` 为空。
- `affected_blocks[]`：每个受影响块给出块地址 `address`、是否擦除 `erase`、
  `erase_size`（擦除时等于 `erase_block_size`，否则 `null`）、块内写入字节数
  `write_bytes`、变化字节数 `changed_bytes`、其中存在 `0 -> 1` 的字节数
  `zero_to_one_bytes`；两个映像完全一致时为空。
- 顶层统计：`erase_count`/`erase_bytes`（擦除字节按整块计）、
  `write_count`/`write_bytes`（实际携带的写字节总量）、
  `changed_bytes` 与 `zero_to_one_bytes`。

### `POST /api/v1/verify-flash-operations`

擦/写操作序列回放校验：与 `/api/v1/plan-flash-update` 一样接收**当前映像 `current_hex`**、
**目标映像 `target_hex`**、Flash 窗口（`flash_start`/`flash_end`）、`erase_block_size`、
`max_write_size`，另外接收一个**有序 `operations` 数组**（`erase`/`write`，按数组顺序
逐条回放）。该接口不生成方案，只回答两个问题：**操作序列本身是否合法**、**全部合法时
回放结果是否与目标映像一致**。

```bash
curl -s -X POST http://localhost:8000/api/v1/verify-flash-operations \
  -H 'Content-Type: application/json' \
  -d '{
    "current_hex": ":10000000000102030405060708090A0B0C0D0E0F78\n:00000001FF\n",
    "target_hex":  ":10000000FF0102030405060708090A0B0C0D0E0F79\n:00000001FF\n",
    "flash_start": 0,
    "flash_end": 256,
    "erase_block_size": 64,
    "max_write_size": 16,
    "operations": [
      {"kind": "erase", "address": 0,  "size": 64, "data_base64": null},
      {"kind": "write", "address": 1,  "size": 15, "data_base64": "AQIDBAUGBwgJCgsMDQ4P"}
    ]
  }' | jq
```

前置校验与差分规划接口完全相同（复用同一解析器与参数校验）：任一 HEX 无效时只返回
各自诊断（`params_valid` 为 `null`，不回放）；窗口/对齐参数不合法或映像越界时
`params_valid=false`、`param_errors` 给出同样的错误码，不回放。

逐条回放规则（在当前映像上维护 NOR Flash 状态，未定义字节按 `0xFF`）：

- `erase`：`address` 必须对齐到 `erase_block_size`，`size` 必须是整块大小的**正整数倍**
  （允许一次连续擦除多个整块），且整个区间位于 Flash 窗口内；执行后该区间字节全部变为
  `0xFF`。
- `write`：区间必须**完整位于 Flash 窗口内**；必须**完全落在单个擦除块内**
  （不允许跨块）；`size` 不得超过 `max_write_size`；`data_base64` 必须可解码
  且携带字节数恰为 `size`（erase 操作该字段为 `null`）；按位检查只能把比特
  **`1 -> 0`**，任何 `0 -> 1`（如 `0x00 -> 0x01`）都非法——NOR 闪存只有先擦除才能
  恢复为 1。
- **首个非法操作即停止回放**：`illegal_index`/`error_code` 给出其下标（0 起）与错误码，
  `operation_error` 含完整信息（消息、相关地址范围），`executed_count` 为此前已成功
  执行的操作数，其后的操作不再执行、也不做目标比对。

操作错误码：`unknown_operation_kind`（kind 非 erase/write）、`operation_outside_flash`
（地址/长度非法或越出窗口或超出 32 位空间）、`erase_not_block_aligned`（擦除未整块对齐）、
`write_crosses_block`（写入跨越擦除块边界）、`write_too_long`（超过 `max_write_size`）、
`write_data_invalid`（write 缺少/无法解码 Base64 载荷）、`write_data_size_mismatch`
（载荷长度与 `size` 不符）、`write_zero_to_one`（写入试图置位，需先擦除）。

全部操作合法后，把**回放结果与目标映像逐字节比较**（任一侧未定义的地址均按 `0xFF`），
将差异地址**合并为极大连续区间** `diffs[]`（`start` 含、`end` 不含），并汇总
`diff_byte_count`。仅当差异为零时 `matches_target=true` 且 **`ok=true`**。

上例（先擦除块 0，再把地址 1..15 写成目标字节；目标首字节为 `0xFF`，擦除后自然满足）
响应：

```json
{
  "ok": true,
  "current_hex_ok": true,
  "target_hex_ok": true,
  "params_valid": true,
  "operations_valid": true,
  "matches_target": true,
  "flash_start": 0,
  "flash_end": 256,
  "erase_block_size": 64,
  "max_write_size": 16,
  "error_count": 0,
  "warning_count": 0,
  "param_errors": [],
  "operation_count": 2,
  "executed_count": 2,
  "illegal_index": null,
  "error_code": null,
  "operation_error": null,
  "diffs": [],
  "diff_byte_count": 0,
  "current_diagnostics": [ ... ],
  "target_diagnostics": [ ... ]
}
```

操作全部合法但回放结果不等于目标时（示意：漏写了地址 1，地址 4..5 也不对，差异自动
合并为连续区间）：

```json
{
  "ok": false,
  "params_valid": true,
  "operations_valid": true,
  "matches_target": false,
  "illegal_index": null,
  "error_code": null,
  "operation_error": null,
  "operation_count": 2,
  "executed_count": 2,
  "diffs": [
    {"start": 1, "end": 2, "size": 1},
    {"start": 4, "end": 6, "size": 2}
  ],
  "diff_byte_count": 3
}
```

- 空操作序列合法：此时等价于直接比较当前映像与目标映像（未定义字节按 `0xFF`）。
- `/api/v1/plan-flash-update` 返回的 `operations`（含 `address`/`size`/`data_base64`）
  可直接作为本接口的 `operations` 提交，规划结果必然通过回放校验。

### `POST /api/v1/validate-vector-table`

Cortex-M 向量表校验：复用 Intel HEX 解析器组装映像，从 `vector_table_start` 起按
**小端 32 位**读取 `vector_count` 个向量（至少 2 个：初始栈顶 + 复位向量），并结合
带 `ram`/`executable` 属性的内存区域逐条校验。任一前置条件无效时不读表。

```bash
curl -s -X POST http://localhost:8000/api/v1/validate-vector-table \
  -H 'Content-Type: application/json' \
  -d '{
    "hex_text": ":020000040800F2\n:1000000000000220010100080000000001020008B9\n:00000001FF\n",
    "vector_table_start": 134217728,
    "vector_count": 4,
    "regions": [
      {"name": "flash", "start": 134217728, "end": 134479872, "ram": false, "executable": true},
      {"name": "ram",   "start": 536870912, "end": 537001984, "ram": true,  "executable": false}
    ]
  }' | jq
```

判定规则：

- HEX 无效时只返回 `diagnostics`（`vectors`/`violations` 为空、`regions_valid` 为
  `null`），不执行向量表校验。
- 区域定义校验与布局接口一致：每个区域须满足 `start < end` 且互不重叠；不合法时
  `regions_valid=false`，`violations` 给出 `invalid_region`/`region_overlap`，不读表。
- 逐条读取向量（条目地址 = `vector_table_start + 4 * index`）：
  - 任一字节缺失 → `missing_vector_bytes`，违规与条目均定位条目序号 `index` 与
    缺失字节地址（条目 `missing_bytes` 列出全部缺失地址），该条目 `status=error`、
    `value=null`；
  - 条目 0（`initial_sp`）：栈顶必须 8 字节对齐（否则 `stack_misaligned`）且落在
    某个 `ram=true` 区域内，**允许等于 RAM 末端**（否则 `stack_outside_ram`）；
  - 条目 1（`reset`）：必须非零（否则 `reset_vector_zero`）；
  - 条目 2+（`handler`）：零向量视为空槽，`status=empty`，不再检查；
  - 所有非零处理器地址（条目 1 起）：必须带 Thumb 位（bit 0，否则
    `thumb_bit_missing`），且清除最低位后的地址须落在某个 `executable=true` 区域内
    （否则 `address_not_executable`）。

上例响应（同样恒为 200；栈顶 `0x20020000` 恰为 RAM 末端，合法）：

```json
{
  "ok": true,
  "hex_ok": true,
  "regions_valid": true,
  "error_count": 0,
  "warning_count": 0,
  "entry_address": null,
  "total_bytes": 16,
  "vector_table_start": 134217728,
  "vector_count": 4,
  "vectors": [
    {"index": 0, "address": 134217728, "role": "initial_sp", "status": "ok",
     "value": 537001984, "target_address": null, "missing_bytes": [],
     "message": "initial SP 0x20020000 inside RAM region 'ram'"},
    {"index": 1, "address": 134217732, "role": "reset", "status": "ok",
     "value": 134217985, "target_address": 134217984, "missing_bytes": [],
     "message": "reset -> 0x08000100 in executable region 'flash'"},
    {"index": 2, "address": 134217736, "role": "handler", "status": "empty",
     "value": 0, "target_address": null, "missing_bytes": [],
     "message": "empty slot (zero vector)"},
    {"index": 3, "address": 134217740, "role": "handler", "status": "ok",
     "value": 134218241, "target_address": 134218240, "missing_bytes": [],
     "message": "handler -> 0x08000200 in executable region 'flash'"}
  ],
  "violations": [],
  "diagnostics": [ ... ]
}
```

- `vectors[]`：逐条结果，`role` 为 `initial_sp`/`reset`/`handler`，`status` 为
  `ok`/`empty`/`error`；`value` 为解析出的小端 32 位字（字节缺失时为 `null`），
  `target_address` 为非零处理器地址清除 Thumb 位后的目标地址。
- `violations[]`：汇总全部违规（区域定义问题 + 逐条向量问题），每条给出 `kind`、
  关联条目 `index`、相关地址 `address` 与区域 `region`（适用时）。
- `ok` 仅在 HEX 有效、区域定义合法且无任何向量违规时为 `true`。

### `POST /api/v1/merge-images`

多映像叠加合并：一次提交**多个带唯一 `name` 的 Intel HEX 映像**，服务复用同一解析器
逐源校验，再按记录 02/04 解析后的**绝对地址**叠加：

- **任一源 HEX 无效即不合并**：返回各源名称与该源的**原始逐行诊断**
  （`sources[].diagnostics`，行号/消息与 `/api/v1/assemble` 完全一致），
  响应不含 `merged_segments`，`total_bytes` 为 0。
- 重叠地址字节相同：正常合并，该字节的来源集合记录**全部写入它的源**；
  字节不同：把连续冲突地址归并为**连续地址段（run）**报告，段内按源给出各自的
  连续值块（`chunks[]`，Base64）；存在任何冲突时响应不含 `merged_segments`。
- 入口地址：**全部缺失**，或所有非空入口值一致时才允许（没有入口的源不参与比较，
  仅一个源给出入口时合并结果采用该入口）；非空值不一致时报告 `entry_conflict`
  （`entries` 为给出入口的各源名→入口值）。
- 成功时按物理连续性输出 Base64 段；当段内的来源集合发生变化（进入/离开重叠区）时
  也会在该地址切分，因此每段的 `sources[]` 对段内每个字节都相同。

```bash
curl -s -X POST http://localhost:8000/api/v1/merge-images \
  -H 'Content-Type: application/json' \
  -d '{
    "images": [
      {"name": "boot", "hex_text": ":020000040800F2\n:0400000000010203F6\n:00000001FF\n"},
      {"name": "app",  "hex_text": ":020000040800F2\n:0400020002030405EC\n:00000001FF\n"}
    ]
  }' | jq
```

上例两源在绝对地址 `0x08000002`/`0x08000003` 以相同字节重叠，成功响应：

```json
{
  "ok": true,
  "sources": [
    {"name": "boot", "ok": true, "error_count": 0, "warning_count": 0, "diagnostics": [ ... ]},
    {"name": "app",  "ok": true, "error_count": 0, "warning_count": 0, "diagnostics": [ ... ]}
  ],
  "entry_address": null,
  "total_bytes": 6,
  "merged_segments": [
    {"start": 134217728, "end": 134217730, "size": 2,
     "data_base64": "AAE=", "sources": ["boot"]},
    {"start": 134217730, "end": 134217732, "size": 2,
     "data_base64": "AgM=", "sources": ["boot", "app"]},
    {"start": 134217732, "end": 134217734, "size": 2,
     "data_base64": "BAU=", "sources": ["app"]}
  ],
  "conflicts": [],
  "entry_conflict": null
}
```

字节冲突时（示意）：

```json
{
  "ok": false,
  "sources": [ ... ],
  "entry_address": null,
  "total_bytes": 3,
  "conflicts": [
    {
      "start": 1, "end": 3, "size": 2,
      "message": "conflicting byte(s) at [0x00000001, 0x00000003): 2 source chunk(s) disagree",
      "chunks": [
        {"source": "a", "start": 1, "end": 3, "size": 2, "data_base64": "AgM="},
        {"source": "b", "start": 1, "end": 3, "size": 2, "data_base64": "CQg="}
      ]
    }
  ],
  "entry_conflict": null
}
```

- `images[]` 至少 1 个且 `name` 非空、**不可重复**；重复或为空列表返回 422。
- `sources[]` 恒按请求顺序给出每个源的 `ok`/计数/原始诊断。
- `conflicts[]` 按地址升序；`chunks[]` 按源在请求中的顺序排列，源在该 run 中
  不连续时会拆成多个 chunk。
- 冲突与 `entry_conflict` 可同时出现；只要任一存在，`ok=false` 且不生成
  `merged_segments` 字段。

### `POST /api/v1/image-digest`

固件内容指纹：复用同一 Intel HEX 解析器组装映像后，把**稀疏段按地址升序编码为
明确的「地址 + 长度 + 字节」帧序列**，并对规范化字节流计算**整像 SHA-256**。
由于只有「绝对地址 + 字节内容」参与哈希，**同一逻辑映像无论怎样切分数据记录、
怎样表示段间空洞（空洞不写入哈希流），指纹都相同**；段自身的帧哈希也绑定地址，
放到不同地址的相同字节段摘要不同。

请求体在 `hex_text` 之外接受可选 `include_entry`（**默认 `true`**）：
为 `true` 时在段帧之后附加入口帧（无入口记录则附加显式「无入口」标记，
避免「无入口」与「未编码入口」混淆）；为 `false` 时**入口地址不参与整像哈希**，
仅散列字节与其安放位置。

```bash
curl -s -X POST http://localhost:8000/api/v1/image-digest \
  -H 'Content-Type: application/json' \
  -d '{
    "hex_text": ":020000040800F2\n:10000000214601360121470136007EFE09D2190141\n:04000005080001C12D\n:00000001FF\n",
    "include_entry": true
  }' | jq
```

规范化字节流（整数一律大端、无符号 64 位）：

```
魔数                          = b"firmware-image-digest/v1\n"
段帧（按地址升序，可多个）     = 0x01 || start:u64 || length:u64 || data[length]
入口帧（include_entry 且有入口）= 0x02 || address:u64
无入口标记（include_entry 且无）= 0x03
整像哈希                       = SHA-256(魔数 || 各段帧 || 入口帧/无入口标记?)
每段摘要                       = SHA-256(该段帧)        # 绑定地址、长度与字节
```

段帧/入口帧用不同标记字节区分，任何一种形状的字节流都不可能被重新解释成另一种。
响应（恒为 200）：

```json
{
  "ok": true,
  "error_count": 0,
  "warning_count": 0,
  "entry_address": 134218177,
  "include_entry": true,
  "total_bytes": 16,
  "image_sha256": "02e4d70d437ce18cdb7c87b204db8fcfba6e1e8af2b0f296864859ba2df93d35",
  "segments": [
    {"index": 0, "start": 134217728, "end": 134217744, "size": 16,
     "gap_before": 0,
     "sha256": "20e1b9b903cbcc066417ba21c589e70fac8c4ce93ba2a3cfdb0ed5ed7f33f1f8"}
  ],
  "manifest": {
    "format": "firmware-image-digest/v1",
    "hash_algorithm": "sha256",
    "include_entry": true,
    "segment_count": 1,
    "total_bytes": 16,
    "frame_count": 2,
    "canonical_bytes": 67,
    "frames": [
      {"kind": "segment", "index": 0, "start": 134217728, "end": 134217744,
       "size": 16,
       "sha256": "20e1b9b903cbcc066417ba21c589e70fac8c4ce93ba2a3cfdb0ed5ed7f33f1f8",
       "address": null},
      {"kind": "entry", "index": null, "start": null, "end": null,
       "size": null, "sha256": null, "address": 134218177}
    ]
  },
  "diagnostics": [ ... ]
}
```

- `image_sha256`：整像指纹，即对上述规范化字节流的 SHA-256。
- `segments[]`：每段摘要，`sha256` 为该段**规范化帧**（标记 + 地址 + 长度 + 字节）
  的哈希；`gap_before` 为与上一段之间的空洞字节数（首段为 0），空洞只用于描述、
  不进入哈希流。
- `entry_address`：最后一个 03/05 记录给出的入口（无则 `null`）；
  `include_entry=false` 时入口仍在响应中回显，只是不参与哈希。
- `manifest`：规范化清单，逐帧列出实际参与哈希的内容（`frames[]` 的
  `kind` 为 `segment` / `entry` / `no_entry`），并给出格式名、算法、
  `frame_count` 与 `canonical_bytes`（被哈希字节流的精确长度），便于独立复核。
- **HEX 解析失败时只返回逐行 `diagnostics`**：`ok=false`、`image_sha256` 与
  `manifest` 为 `null`、`segments` 为空、`total_bytes` 为 0，不产出任何摘要。
  纯警告（如空行、相同字节重写）不影响指纹。

同映像不同表示的指纹一致性（示意）：把 16 字节拆成 1 条记录或 3 条记录，
`image_sha256` 完全相同；`include_entry` 在两种表示上分别取默认值或 `false`
时也各自相同。只改一个字节、移动安放地址或改变入口地址才会改变默认指纹；
其中仅改变入口地址时，`include_entry=false` 的「字节/安放」指纹保持不变。

### `POST /api/v1/export-hex`

Intel HEX 规范化导出：复用同一解析器组装映像后，把连续映像**确定性地重排为数据记录**
并重新输出 HEX 文本。导出结果只取决于组装后的映像与导出参数，与输入的记录切分方式、
空洞表示或基址记录风格（02/04）无关；对导出结果再次导出会得到逐字节相同的文本
（不动点）。

```bash
curl -s -X POST http://localhost:8000/api/v1/export-hex \
  -H 'Content-Type: application/json' \
  -d '{
    "hex_text": ":020000040800F2\n:10000000214601360121470136007EFE09D2190141\n:04000005080001C12D\n:00000001FF\n",
    "max_data_bytes": 16,
    "include_entry": true
  }' | jq
```

导出规则：

- 数据记录（类型 00）每条最多携带 `max_data_bytes` 字节（**1..255**，默认 16），
  按地址升序连续切分；
- **任何数据记录都不跨越 64 KiB 地址窗口**（`地址 >> 16`）：到达窗口末尾即截断，
  窗口切换时先输出一条扩展线性地址记录（类型 04）再继续（初始窗口 0 按 Intel HEX
  约定无需输出，保持最小必要数量）；
- 所有记录的**二补校验和全部重算**，输出统一为大写十六进制、以 EOF 记录结尾；
- `include_entry=true`（默认）且映像带入口地址时，在 EOF 前附加一条线性入口记录
  （类型 05，03 型段入口也会规范化为 05 型）；为 `false` 时入口不写入导出文本，
  但仍在响应中回显。

上例请求本身已是规范形态，响应（恒为 200）：

```json
{
  "ok": true,
  "error_count": 0,
  "warning_count": 0,
  "entry_address": 134218177,
  "total_bytes": 16,
  "max_data_bytes": 16,
  "include_entry": true,
  "exported_hex": ":020000040800F2\n:10000000214601360121470136007EFE09D2190141\n:04000005080001C12D\n:00000001FF\n",
  "record_count": 4,
  "data_record_count": 1,
  "extended_address_record_count": 1,
  "entry_record_count": 1,
  "diagnostics": [ ... ]
}
```

- `exported_hex`：导出的规范化 HEX 文本（含结尾换行）；`record_count` 为含 EOF 的
  总记录数，`data_record_count`/`extended_address_record_count`/`entry_record_count`
  分别给出数据记录、扩展线性地址记录与入口记录的数量。
- 跨窗口示例：32 字节数据位于 `0xFFF0`、`max_data_bytes=255` 时，导出为
  `0xFFF0` 处 16 字节 → 类型 04 切换到窗口 1 → 偏移 `0x0000` 处 16 字节 → EOF。
- **HEX 解析失败时只返回逐行 `diagnostics`**：`ok=false`、`exported_hex` 为 `null`、
  各记录数为 0、`total_bytes` 为 0，不生成任何文本；`max_data_bytes` 越界
  （<1 或 >255）返回 422。

## 解析规则

- 每行必须形如 `:llaaaatt<data>cc`；校验 `ll`（字节数）与实际数据长度一致，
  且全部字节（含 `cc`）之和 ≡ 0 (mod 256)（二补校验和）。
- 支持的记录类型：
  - `00` 数据：写入 `当前基址 + 记录内偏移`；
  - `01` EOF：必须唯一且位于末行，其后出现任何记录（含第二个 EOF）均报错，缺失 EOF 同样报错；
  - `02` 扩展段地址：基址 = 值 << 4；
  - `03` 段入口（CS:IP）：入口 = CS << 4 + IP；
  - `04` 扩展线性地址：基址 = 值 << 16；
  - `05` 线性入口：入口 = 32 位值。
- 同一地址重复写入相同字节：接受（诊断中注明 identical rewrite）；
  写入冲突字节：报错并给出当前行号、冲突地址与首次写入的行号，保留首次写入的值。
- 校验失败的记录不会写入映像；空行忽略并记 warning。

## 项目结构

```
app/
  main.py         # FastAPI 应用与请求/响应模型
  hex_parser.py   # Intel HEX 解析与映像组装（纯逻辑，可独立测试）
  layout.py       # 内存布局校验（区域定义检查、段切分、占用统计，纯逻辑）
  relocation.py   # 整体重定位规划（可行 delta 闭区间求交合并、选最小位移，纯逻辑）
  flash_update.py # Flash 差分烧写规划（逐块比较、擦除判定、run 合并与切分，纯逻辑）
  flash_verify.py # 擦/写操作序列回放校验（逐条合法性、1->0 语义、目标差异合并，纯逻辑）
  vector_table.py # Cortex-M 向量表校验（小端读取、栈顶/复位/Thumb 位与区域归属，纯逻辑）
  image_merge.py  # 多映像按绝对地址叠加合并（同值归并、冲突段报告、入口一致性，纯逻辑）
  image_digest.py # 整像内容指纹（段帧规范化编码 + 整像/每段 SHA-256 + 规范化清单，纯逻辑）
  hex_export.py   # Intel HEX 规范化导出（确定性记录重排、64 KiB 窗口切分、校验和重算，纯逻辑）
tests/
  test_hex_service.py           # 解析器与 assemble 接口
  test_validate_layout.py       # validate-layout 接口与布局逻辑
  test_plan_relocation.py       # plan-relocation 接口与重定位逻辑
  test_plan_flash_update.py     # plan-flash-update 接口与烧写规划逻辑
  test_verify_flash_operations.py # verify-flash-operations 接口与回放校验逻辑
  test_validate_vector_table.py # validate-vector-table 接口与向量表校验逻辑
  test_merge_images.py          # merge-images 接口与多映像合并逻辑
  test_image_digest.py          # image-digest 接口与内容指纹逻辑（分片/空洞不变性等）
  test_export_hex.py            # export-hex 接口与规范化导出逻辑（窗口切分、不动点等）
Dockerfile
docker-compose.yml
requirements.txt       # 运行依赖
requirements-dev.txt   # 测试依赖
```
