# S-DES 开发手册与公共 API

## 1. 模块职责和开发约定

本项目采用 Python 实现。`sdes.py` 和 `analysis_tools.py` 仅依赖标准库；`gui.py` 与 `scripts/capture_gui.py` 使用 PyQt5。运行证据记录的开发环境为 Windows 11、CPython 3.13.5，详细版本与解释器路径见 `results/summary.json`。

| 文件或目录 | 职责 |
|---|---|
| `sdes.py` | 参数、严格位串解析、子密钥、分组/字节/ASCII 加解密、逐步轨迹 |
| `analysis_tools.py` | 已知明文穷举、固定明文分桶、全明文扫描、全局等价密钥 |
| `gui.py` | Qt 主窗口、输入校验、结果展示、后台分析线程 |
| `cli.py` | argparse 命令行入口，调用与 GUI 相同的核心 |
| `reference_sdes.py` | 不导入核心的独立位串实现 |
| `tests/` | 输入、算法、全空间、ASCII、攻击和交换文件验证 |
| `scripts/run_evidence.py` | 重跑测试，生成五关计算证据、环境与哈希清单 |
| `scripts/compare_cross_vectors.py` | 比较实际提供的外部 JSON/CSV 向量 |
| `scripts/capture_gui.py` | 操作真实 Qt 控件，保存静态截图、检查结果和真实任务计时 |
| `results/` | 计算结果、完整映射和 SHA-256 证据清单 |
| `artifacts/gui/` | GUI 静态截图和捕获元数据 |

所有位的位置从左起按 1 编号。主密钥整数范围为 `0..1023`，分组为 `0..255`。`bool` 虽然是 Python 的整数子类，仍作为无效数值拒绝。位串输出保留前导零。

置换表和作业 S 盒见 `requirements.md` 与源码常量，已逐项读取石墨公式与图示并视觉核对。源文 `SPBox=(2,4,3,1)` 在代码中命名为 `P4`。修改参数时必须同时修正核心和独立参考实现，重新生成证据，不能只改报告里的数字。

## 2. 算法与性能实现

`permute(value, table, input_width)` 从输入整数按位置表依次取位。`_rotate_half()` 对一个 5 位半块循环左移；`_shift_halves()` 对 P10 的两半分别操作。

`generate_subkeys()` 默认 `schedule='assignment'`：K1 从 P10 状态总移 1 位，K2 从同一状态总移 2 位。`schedule='cumulative'` 的总移位为 1、3 位。调度名称必须显式传播到加密、解密、ASCII、攻击和证据生成，禁止不同调用自行选择不同解释。

一轮计算为：右半块 EP 扩展 → 与子密钥异或 → 两个 S 盒 → 拼接 4 位输出 → P4 → 与左半块异或。首轮完成后交换左右半块，第二轮后直接执行 IP 逆置换。解密只交换子密钥次序。

核心优化保留公式的可读实现：

- `_subkeys()` 用 `lru_cache(maxsize=2048)` 缓存 1024 个密钥在两种调度下的子密钥。
- `_IP_TABLE`、`_IP_INV_TABLE` 保存各 256 个分组的置换结果。
- `_F_TABLE` 保存 `16 × 256` 个 `(右半块,子密钥)` 的 F 函数值，由 `_f()` 公式生成。
- `_crypt_with_subkeys()` 复用已生成子密钥和查表结果，避免扫描时重复计算。
- `trace_block()` 逐项计算 EP、异或、S 盒和 P4，以输出可人工核查的中间值；其结果与快路径在测试中比较。

下划线开头的函数和查表属于内部实现，业务层优先使用公共 API。`analysis_tools.py` 在已验证参数后调用内部 `_crypt_with_subkeys()`，仅用于降低全空间扫描开销。

## 3. 核心公共 API

除明确列出的 `decrypt` 参数外，密钥相关函数均默认 `schedule='assignment'`。可选值只有 `assignment`、`cumulative`。

| 接口 | 返回值与约定 |
|---|---|
| `parse_bits(text: str, width: int) -> int` | 严格要求恰好 width 个 `0/1`；不自动去除空白，也不接受 `0b` 前缀 |
| `format_bits(value: int, width: int) -> str` | 校验范围并输出补齐前导零的位串 |
| `permute(value: int, table: tuple[int,...], input_width: int) -> int` | 校验输入宽度、数值与表位置；位置从1开始，可重复；空表返回0；非法输入抛出 `ValueError` |
| `generate_subkeys(key: int, schedule='assignment') -> tuple[int,int]` | 返回整数 K1、K2，各 8 位 |
| `encrypt_block(block: int, key: int, schedule='assignment') -> int` | 加密一个 8 位分组 |
| `decrypt_block(block: int, key: int, schedule='assignment') -> int` | 解密一个 8 位分组 |
| `encrypt_bytes(data: bytes, key: int, schedule='assignment') -> bytes` | 每个字节独立加密，无填充，输出长度不变 |
| `decrypt_bytes(data: bytes, key: int, schedule='assignment') -> bytes` | 对应逐字节解密；拒绝 `bytearray` 等非 bytes 输入 |
| `encrypt_ascii(text: str, key: int, schedule='assignment') -> bytes` | 严格 ASCII 编码后加密 |
| `decrypt_ascii(data: bytes, key: int, schedule='assignment') -> str` | 解密后严格 ASCII 解码 |
| `trace_key_schedule(key: int, schedule='assignment') -> dict` | 输出 P10、两半、总左移、P8 和两个子密钥 |
| `trace_block(block: int, key: int, decrypt=False, schedule='assignment') -> dict` | 输出完整加密/解密轨迹，`decrypt` 必须是布尔值 |

示例：

```python
from sdes import parse_bits, format_bits, encrypt_block, decrypt_block, trace_block

key = parse_bits('1010000010', 10)
plaintext = parse_bits('11010111', 8)
ciphertext = encrypt_block(plaintext, key, schedule='assignment')
assert format_bits(ciphertext, 8) == '11101000'
assert decrypt_block(ciphertext, key, schedule='assignment') == plaintext
trace = trace_block(plaintext, key, schedule='assignment')
assert trace['output_int'] == ciphertext
```

### 轨迹数据结构

`trace_block()` 返回可直接传给 `json.dumps()` 的字典，没有 Qt 对象、bytes 或 datetime 对象。位串与整数分别用无后缀字段和 `_int` 字段表示。

| 顶层字段 | 内容 |
|---|---|
| `input`、`input_int` | 输入 8 位串和整数 |
| `key`、`schedule`、`decrypt` | 主密钥位串、调度名称、是否解密 |
| `subkeys` | `K1`、`K2` 的 8 位串；`used` 是实际使用顺序的名称列表，例如 `['K2','K1']` |
| `IP` | 初始置换后的 8 位串 |
| `rounds` | 两个逐轮字典，结构见下表 |
| `SW` | 首轮输出交换左右半块后的 8 位串 |
| `IPinv`、`output`、`output_int` | 逆置换结果、最终位串、最终整数 |
| `key_schedule` | `trace_key_schedule()` 的完整返回值 |

每个 `rounds` 元素包含：

| 字段 | 内容 |
|---|---|
| `number`、`subkey_name`、`subkey` | 轮号、实际子密钥名称及 8 位串 |
| `input`、`left`、`right` | 本轮输入及两个 4 位半块 |
| `EP`、`xor` | 扩展右半块和与子密钥异或后的 8 位串 |
| `SBOX1`、`SBOX2` | 每项均含 `input`（4 位）、`row`、`column`（0..3）、`output`（2 位）、`output_int` |
| `SBOX_output`、`P4` | 两个 S 盒拼接输出及置换结果，各 4 位 |
| `newLeft` | 左半块与 P4 输出异或后的 4 位串 |
| `output`、`output_int` | `(newLeft || right)` 的本轮输出 |

`trace_key_schedule()` 顶层包括 `input`、`input_int`、`schedule`、`P10`、原始 `left/right`、`K1/K2` 和 `rounds`。其中每轮包括 `number`、`total_left_shift`、移位后的 `left/right`、拼接位串 `shifted`、`P8` 及 `subkey_int`。总移位始终相对于 P10 的原始两半。

## 4. 攻击与碰撞 API

`Progress` 回调签名为 `progress(done, total, candidates_so_far, elapsed_seconds)`。计时字段使用 `perf_counter()`；`started_at`、`finished_at` 使用带本机时区偏移的 ISO 8601 字符串。

### `brute_force(pairs, schedule='assignment', progress=None) -> dict`

`pairs` 是非空的 `(明文整数,密文整数)` 可迭代对象，支持列表和生成器；输入会先完整校验并收集，空列表和空迭代器都拒绝。每个整数都必须是合法 8 位值。枚举 0..1023 全部密钥并保留满足所有对的密钥，结果按密钥升序。

返回字段：`schedule`、`pairs`（每项含明密文位串与整数）、`candidate_keys`（整数列表）、`candidate_key_bits`、`candidate_count`、`tested_keys`、`total_keys`、`elapsed_seconds`、`started_at`、`finished_at`。正常完成时 `tested_keys=total_keys=1024`。

回调先调用 `(0,1024,0,0.0)`，之后每检查一个密钥调用一次，共 1025 次。回调异常向调用者传播；当前 GUI 没有提供取消操作。零候选是正常分析结果，不是异常；它表示输入对或调度不相容。多候选不能解释为唯一密钥。

### `collision_analysis(plaintext, schedule='assignment') -> dict`

固定合法 8 位明文，枚举全部密钥并按密文分组。返回 `plaintext`、`plaintext_int`、`schedule`、`total_keys`、`groups`、`ciphertext_groups`、`collision_examples`、`statistics` 和时间字段。

`groups` 按密文升序，每组有 `ciphertext`、`ciphertext_int`、`count`、整数 `keys` 和 `key_bits`；包含单元素组。`ciphertext_groups` 为“密文位串 → 密钥位串列表”的字典。`collision_examples` 最多 10 个示例，每项展示其中两个密钥，并给出完整桶大小；完整密钥仍保存在 groups 中。

`statistics` 包括不同密文数、非空/空桶数、非空桶的最小/最大/平均大小、碰撞桶数、碰撞桶内的密钥总数、无序碰撞密钥对数和桶大小直方图。`min_bucket_size` 与 `mean_bucket_size` 都只针对非空桶；`empty_buckets` 单独记录空桶。每桶 n 个密钥贡献 `n(n-1)/2` 个无序密钥对。

### 完整扫描接口

| 接口 | 结果 |
|---|---|
| `scan_all_plaintexts(schedule='assignment', progress=None)` | 扫 256 个明文，每个枚举 1024 个密钥；保存 256 份摘要和总体最小/最大不同密文数、最大桶等，不重复保存每个明文的所有桶 |
| `equivalent_key_analysis(schedule='assignment', progress=None)` | 对每个密钥构造完整 256 字节加密置换，按置换完全相同分组 |

扫描结果的逐明文摘要位于 `plaintexts`，另有 `encryptions=262144`、`all_plaintexts_have_collisions` 和时间字段。扫描回调的第三项表示已发现碰撞的明文数量。

等价分析返回 `distinct_permutations`、所有 `equivalence_groups`、仅含多密钥的 `equivalent_groups`、`equivalent_group_count`、`keys_in_equivalent_groups`、`largest_equivalence_group` 等。组元素均有 `keys`、`key_bits`、`count`。其回调第三项表示目前不同置换数。

`all_plaintext_collision_analysis` 是 `scan_all_plaintexts` 的别名；`analyze_equivalent_keys` 是 `equivalent_key_analysis` 的别名。

## 5. 校验、异常与展示层

| 情况 | 核心行为 |
|---|---|
| width 不是正整数；位串类型、字符、位数错误 | `ValueError` |
| 分组/密钥不是整数、是 bool 或超出范围；未知 schedule | `ValueError` |
| bytes API 收到非 bytes；ASCII 加密收到非 str | `TypeError` |
| 非 ASCII 明文 | `UnicodeEncodeError` |
| 解密字节超出 ASCII 范围 | `UnicodeDecodeError` |
| 空明密文对、结构错误或非法 8 位数值 | `ValueError` |
| 不相容但合法的明密文对 | 正常返回 0 个候选 |

严格 ASCII 解码只检查编码范围；错误密钥也可能偶然产生合法 ASCII，成功解码不能作为密钥正确或数据完整的证明。

GUI 在调用 `parse_bits()` 前对位输入执行 `.strip()`，核心本身不剔除空白。GUI 的攻击输入每行用空白、英文/中文逗号分隔两个位串；CLI 还支持冒号分隔和 `#` 开头的注释行。CLI 接受 Hex 中的空白，Base64 采用严格校验；GUI 会先去除 Base64 输入中的空白。解析失败均明确提示，不默默丢弃字符。

GUI 捕获异常并在状态栏显示错误；位串/ASCII 错误会撤下相关旧输出及旧计数字样。暴力破解/碰撞输入校验失败时不启动 worker，清除该页的旧报告、进度和计时。后台任务失败会清除结果并显示真实结束时间和失败前耗时；线程结束后恢复输入与按钮。CLI 通过 `argparse.parser.error()` 输出信息并以状态码 2 退出。普通成功 CLI 命令返回 0。

## 6. Qt 后台任务与信号

`SDESWindow` 提供位串、ASCII、暴力破解、密钥碰撞四个页签。位串和 ASCII 运算直接调用公共 API；暴力破解和固定明文碰撞使用 `AnalysisWorker(QThread)`。

开始任务前，主线程校验并取得输入快照，锁定所有操作输入、密文格式、调度选择和操作按钮，创建带 `kind/payload/schedule` 的 worker。已有 worker 时拒绝启动第二个分析任务，并保留当前运行状态。worker 只计算与发信号，不直接修改控件。

`AnalysisWorker` 的信号为 `progress(int,int,object,float)`、`completed(object)`、`failed(str)`。暴力攻击仍真实检查全部密钥，但只有每 32 个检查点及终点向 GUI 发出进度信号，避免事件排队过多；不添加人为 sleep。碰撞任务没有逐钥进度条，只显示执行状态与完成结果。

完成报告含 `kind`、`schedule`、核心开始/结束时间、核心耗时、`worker_elapsed_seconds` 与原始 `result`。核心耗时表示分析函数的计算区间；worker 总耗时包含模块加载和信号前的处理，二者不要混用。GUI 显示全部候选与全部固定明文桶。

worker 的 `finished` 信号恢复控件、清除 `self.worker` 并 `deleteLater()`。窗口关闭时若 worker 仍运行，`closeEvent()` 等待其结束，避免 QThread 随窗口销毁。当前实现没有取消按钮；分析任务规模有限。

窗口还发出 `taskStarted`、`taskProgress`、`taskCompleted`、`taskFailed` 信号，供截图脚本记录真实任务事件并验证完成结果。当前只保存静态截图和计时；动态演示已删除，第 4 关要求的视频或动图提交证据未保留。

## 7. 独立验证和证据复现

在项目根目录运行：

```powershell
python -m unittest discover -s tests -v
python scripts/run_evidence.py
python scripts/capture_gui.py
```

`reference_sdes.py` 不导入 `sdes`，不复用其参数对象、缓存表或算法函数；它独立声明作业参数，使用字符串索引、循环移位和字符异或计算。两份实现一致说明本地实现相互支持；此外，已与同学小组使用作业示例明文、密文和密钥完成交叉核对。

本次测试数量和真实运行时间见 `results/unit_tests.json` 与逐关测试报告；两种模式分别对全部 262144 个密钥/明文组合比较核心与独立实现的加密结果，并检查核心解密参考密文、参考实现解密核心密文均还原原文，总计 524288 个组合。每种模式的 1024 个固定密钥双射通过，并分别比较 1024 对子密钥。新增 GUI 回归测试检查错误结果撤销、输入冻结及失败恢复；没有 PyQt5 时会跳过这些 GUI 测试，而完整证据生成要求全部测试实际通过、无跳过。

`scripts/run_evidence.py` 还生成手算向量、128 条交换向量、ASCII 结果、逐输入对数的攻击结果、两个模式的全明文碰撞扫描和全局等价分析。`full_mapping_<schedule>.bin` 为 1024×256 个无符号字节，偏移 `key * 256 + plaintext` 给出该密钥/明文的密文。脚本从该映射重新统计桶并核对分析函数结果。`summary.json` 记录环境和源码 SHA-256；`evidence_manifest.json` 记录结果文件大小与 SHA-256。

交换 CSV 列为 `schedule,key_bits,plaintext_bits,ciphertext_bits`；JSON 使用 `{"vectors":[...]}` 或同字段的数组。比较脚本检查加密结果与解密回原文，记录来源文件路径、SHA-256、来源说明和差异；成功退出0，有差异退出1，非法输入退出2并写 `successful=false`、`status=invalid_input` 的失败报告，避免残留上次成功记录。报告还包含 `vectors_supplied` 和 `input_errors`。输出路径不能与输入文件相同。该工具支持对交换向量进行机器化复核。

`scripts/audit_submission.py` 是只读材料审核：核对文档本地链接、测试计数/名称/完整覆盖记录、计算与 GUI 的来源文件 SHA-256、结果与截图大小和 SHA-256。源码或证据变化后须重生成对应记录；审核通过用于检查材料内部一致性。

## 8. 默认调度为何忽略主密钥第 2 位

设主密钥从左到右为 `k1..k10`。先 P10，再分别将两半左移，最后 P8，得到子密钥中各位对应的**原始主密钥位置**：

| 子密钥来源 | 被选择的原始位置 |
|---|---|
| 总左移 1 位（K1） | `(1,7,9,4,8,3,10,6)` |
| 总左移 2 位（assignment K2） | `(9,4,8,3,6,5,1,10)` |
| 总左移 3 位（cumulative K2） | `(8,3,6,5,10,2,9,1)` |

前两行的并集是 `{1,3,4,5,6,7,8,9,10}`，不包含原始第 2 位。因此默认模式中翻转该位不改变 K1/K2，自然不改变任何明文的加密或解密结果。按 10 位整数表示，从左数第 2 位权值为 `2^8=256`，每个密钥 K 的等价伙伴为 `K xor 256`。

完整置换分析进一步确认：默认模式恰好有 512 个两密钥等价类、512 种不同置换；没有其他合并。以 `1010000010` 为例，等价伙伴为 `1110000010`。即使加入全部 256 个明密文对也只能确定这对候选，不能唯一恢复第 2 位。

兼容模式的第二子密钥选择第 2 位；本次完整置换分析得到 1024 种不同置换，没有全局等价钥。这是按当前参数计算的结果，并不意味着一个明密文对就能唯一识别密钥。

本次全明文分桶结果还显示：默认模式每个明文有 254 种不同密文，最大桶 8；兼容模式有 238–240 种不同密文，最大桶 12。固定明文碰撞和全局等价必须分别记录：1024 个密钥映射到至多 256 个密文必然碰撞，但不能仅据此证明两个密钥在全部明文上等价。

## 9. 修改与重新验收

修改参数或调度时先记录来源与解释，再分别修改核心和独立参考实现，更新手算固定值与预期测试，运行测试及两个证据脚本。检查 `summary.json` 的参数、调度、源码哈希、统计和 GUI 捕获清单与当前代码一致。若只有文档更新，不应改写既有时间戳冒充重新计算。

新增调用方必须传递所选 schedule；保持 public API 的严格输入与返回结构，尤其不能把 bytes 密文直接用 ASCII 编码保存，或让攻击在首个候选处停止。
