# 实验一：S-DES 五关验收报告

**第1、3、5关已实现并通过本机验证；第4关实现与计算验证通过，当前仅保留静态截图和计时，动态演示已删除；第2关仅完成本地独立实现对照，真实他组、不同语言或平台的互测尚未完成。** 本报告对照[石墨作业](https://shimo.im/docs/m5kvdlMaKvcENy3X)，验收范围见[需求分析](requirements.md)。

| 关卡 | 本次结论 | 主要证据 |
|---|---|---|
| 第1关：基本测试 | 8位加解密、10位密钥、GUI与输入校验通过 | 手算向量、完整域测试、加解密截图 |
| 第2关：交叉测试 | 本地两实现通过；真实外组互测待补 | 双向互解、128条交换向量 |
| 第3关：扩展功能 | ASCII逐字节处理与Hex/Base64往返通过 | ASCII/字节向量、GUI截图 |
| 第4关：暴力破解 | 实现与计算验证通过；动态演示提交证据未保留 | 单对/多对记录、真实计时与静态截图 |
| 第5关：封闭测试 | 分桶、全明文扫描和等价钥分析通过 | 完整映射、统计、碰撞反例 |

## 1. 证据、环境与算法条件

数值来自[计算汇总](../results/summary.json)、[单元测试记录](../results/unit_tests.json)、[原始日志](../results/unit_tests.txt)和[GUI捕获清单](../artifacts/gui/capture_manifest.json)。截图和计算为不同运行，保留各自真实时间。

| 项目 | 实际记录 |
|---|---|
| 环境 | Windows 11 `10.0.26200`，CPython 3.13.5，64位，`E:\anaconda3\python.exe` |
| 计算生成开始/结束与耗时 | 见[计算汇总的当前运行记录](../results/summary.json) |
| 42项测试开始/结束与耗时 | 见[单元测试的当前运行记录](../results/unit_tests.json) |
| 42项测试结果 | 全部通过；失败0、错误0、跳过0 |
| GUI捕获 | offscreen，1140×860；26项检查全部通过，保存10张静态截图；时间见[当前捕获清单](../artifacts/gui/capture_manifest.json) |
| 时钟 | 时间戳含 `+08:00`；耗时由 `time.perf_counter()`测量 |

核心使用作业参数，不调用现成密码库。置换按输入左侧第1位编号；S盒由外侧两位选行、中间两位选列。第二轮后不交换半块，解密颠倒子密钥次序。

```text
P10   = (3,5,2,7,4,10,1,9,8,6)     P8 = (6,3,7,4,8,5,10,9)
IP    = (2,6,3,1,4,8,5,7)          IP^-1 = (4,1,3,5,7,2,8,6)
EP    = (4,1,2,3,2,3,4,1)          P4 = (2,4,3,1)
SBOX1 = ((1,0,3,2),(3,2,1,0),(0,2,1,3),(3,1,0,2))
SBOX2 = ((0,1,2,3),(2,3,1,0),(3,0,1,2),(2,1,0,3))
```

石墨公式 `K_i=P8(Shift^i(P10(K)))` 与课件常见累积移位流程有解释差异；程序将它们显式区分，所有入口共用所选模式。

| 模式 | K1相对P10总左移 | K2相对P10总左移 | 用途 |
|---|---:|---:|---|
| `assignment` | 1 | 2 | 默认，作业公式字面解释 |
| `cumulative` | 1 | 3 | 先LS-1、再额外LS-2的兼容流程 |

## 2. 第1关：基本加解密与GUI

**结果：通过本机验证。** GUI接受8位明文/密文和10位密钥，保留前导零，拒绝非法长度、非二进制字符、密钥及分组。手算样例密钥为 `1010000010`，明文为 `10011010`，详见[手算与双实现轨迹](../results/hand_vectors.json)。

| 模式 | P10 | K1 | K2 | 密文 | 解密还原 |
|---|---|---|---|---|---|
| assignment | `1000001100` | `10100100` | `10010010` | `11101111` | `10011010` |
| cumulative | `1000001100` | `10100100` | `01000011` | `01101011` | `10011010` |

默认模式中间值：`IP=00011011`，首轮异或 `01110011`、S盒输出 `0011`、P4输出 `0110`、首轮状态 `01111011`；交换后 `10110111`，第二轮异或 `00101100`、S盒输出 `0001`、P4输出 `0100`，逆置换得到 `11101111`。固定期望值与整数及独立字符串轨迹逐项核对。

| 完整域验证 | assignment | cumulative | 合计 |
|---|---:|---:|---:|
| 两实现加密相同的密钥/明文组合 | 262144 | 262144 | 524288 |
| 核心解密参考密文还原原文 | 262144 | 262144 | 524288 |
| 参考实现解密核心密文还原原文 | 262144 | 262144 | 524288 |
| 固定钥的256明文双射 | 1024 | 1024 | 2048 |
| 子密钥对照 | 1024 | 1024 | 2048 |

截图使用明文 `10101010`、同一密钥，默认密文为 `00001001`；它与上方手算样例是不同输入。

![位串加密与逐轮轨迹](../artifacts/gui/01_bits_encrypt.png)

![位串解密还原输入](../artifacts/gui/02_bits_decrypt.png)

## 3. 第2关：独立实现与真实外组互测

**结果：本地对照通过，真实外组互测未完成。** `reference_sdes.py` 独立声明参数并使用字符串运算，不导入整数核心；上表524288组验证加密一致和双向互解。另导出[128条JSON向量](../results/cross_vectors.json)与[CSV向量](../results/cross_vectors.csv)，每种模式64条。

当前 `external_group_test_status=not_performed`。两份程序在本机、同语言下运行；自生成向量是互测准备材料，不能声明为真实外组证据。完成本关仍需另一组身份、语言/平台、同步参数与调度、实际交换文件及双方互解记录。

```powershell
python scripts/compare_cross_vectors.py other_group_vectors.csv --implementation core --source-label "实际组号、语言与平台" --output results/external_vector_comparison.json
```

CSV字段为 `schedule,key_bits,plaintext_bits,ciphertext_bits`，JSON支持 `{"vectors":[...]}` 或向量数组。脚本检查加密和解密还原，记录来源、SHA-256及差异：成功退出0、不一致退出1、非法输入退出2并写 `successful=false`、`status=invalid_input` 与 `input_errors`，防止残留旧成功报告；输出不能覆盖输入。

## 4. 第3关：ASCII扩展

**结果：通过本机验证。** 每个ASCII字符作为8位字节独立加解密，无填充；原始字节另有API。GUI用Hex/Base64表示密文，避免不可打印密文字节丢失。数据见[ASCII与字节证据](../results/ascii_vectors.json)。

| 每种模式的输入 | 字节数 | 两种模式的结果 |
|---|---:|---|
| 空串 | 0 | 往返且两实现一致 |
| NUL、TAB、LF、CR、ESC、DEL | 6 | 控制字符完整保留 |
| `Hello S-DES!` | 12 | 往返且两实现一致 |
| ASCII 0–127全部字符 | 128 | 全部往返且两实现一致 |
| 原始字节0–255 | 256 | 全部往返且两实现一致 |

共10组计算案例；另4种非ASCII输入（中文、`é`、表情、含U+0080文本）均拒绝。普通样例assignment密文Hex为 `e45c8989abc2cb569b30cbad`，cumulative为 `c4f80d0d2f624f365f504f29`。捕获检查实际执行Hex/Base64往返及非法ASCII、Hex、Base64错误提示。

![ASCII Hex加解密](../artifacts/gui/03_ascii_hex.png)

[ASCII Base64界面](../artifacts/gui/04_ascii_base64.png)单独保存，可与Hex界面对照。

## 5. 第4关：暴力破解与计时

**结果：实现与计算验证通过；动态演示提交证据未保留。** 作业要求以视频或动图展示运行与耗时；动态演示已删除，当前仅保留静态截图和真实计时。原钥 `1010000010`，依次加入下表明文及其真实密文，每轮重新枚举全部1024钥，保留同时满足全部输入对的所有候选，不在首个命中处停止。

| 对数 | 新增明文 | assignment候选 | cumulative候选 |
|---:|---|---:|---:|
| 1 | `11010111` | 6 | 3 |
| 2 | `10011010` | 2 | 3 |
| 3 | `00000000` | 2 | 2 |
| 4 | `11111111` | 2 | 2 |
| 5 | `01010101` | 2 | 1 |
| 6 | `10101010` | 2 | 1 |

每轮包含原钥、检查1024钥、发出1025次进度回调，候选集合与独立参考枚举相同。完整输入、候选、时间戳与各轮实测耗时见[assignment当前记录](../results/brute_force_assignment.json)与[cumulative当前记录](../results/brute_force_cumulative.json)。

assignment第二对后剩 `1010000010`、`1110000010`，之后仍有两者，不能误称唯一恢复；cumulative第五对起仅剩原钥。矛盾输入返回零候选，空输入和空迭代器拒绝。

GUI单对使用 `10101010 → 00001001`，有4个候选，5对后剩2个。开始/结束时间与实测耗时见[GUI当前捕获清单](../artifacts/gui/capture_manifest.json)中的任务报告。这是GUI后台分析的另一次运行，算法时间包含进度回调，不能与计算证据混为同次测量，也不能当作线程总耗时。

![单对破解的全部候选与计时](../artifacts/gui/05_brute_single_pair.png)

![多对同时筛选候选](../artifacts/gui/06_brute_multiple_pairs.png)

## 6. 第5关：封闭测试、碰撞与等价密钥

**结果：通过本机验证。** 固定明文 `10011010` 枚举1024钥按密文分桶，见[assignment分桶](../results/collision_buckets_assignment.json)与[cumulative分桶](../results/collision_buckets_cumulative.json)。

| 固定明文统计 | assignment | cumulative |
|---|---:|---:|
| 不同密文/非空桶 | 254 | 239 |
| 空桶 | 2 | 17 |
| 非空桶最小/最大钥数 | 2 / 8 | 1 / 12 |
| 碰撞桶数 | 254 | 223 |
| 碰撞桶内钥数 | 1024 | 1008 |
| 无序碰撞密钥对数 | 1720 | 2240 |

固定8位明文时，1024钥映射到至多256种密文，至少一个桶有4把钥，碰撞必然存在；单个明文上的碰撞不能证明全局等价。进一步扫描全部256明文并比较每把钥的完整256字节加密置换：

| 完整扫描与等价分析 | assignment | cumulative |
|---|---:|---:|
| 扫描加密组合 | 262144 | 262144 |
| 每明文不同密文范围 | 254–254 | 238–240 |
| 全域最大桶 | 8 | 12 |
| 不同完整加密置换 | 512 | 1024 |
| 大于1的全局等价类 | 512 | 0 |
| 最大等价类大小 | 2 | 1 |

assignment的两次子密钥选取均遗漏原始主密钥第2位，翻转它不改变K1/K2；等价伙伴为 `K xor 256`。完整分析确认512个双钥类，任何更多明密文对都不能区分 `1010000010`、`1110000010`。cumulative的K2包含该位，当前参数下没有全局等价钥；不表示一个输入对足够识别密钥。推导见[开发手册](developer_manual.md)。

非等价碰撞反例：assignment密钥 `0001001111`、`0010010011` 对明文 `10011010` 都得到 `00000000`，但对 `00000001` 分别得到 `00110001`、`11111101`。详情见[碰撞反例](../results/collision_examples_assignment.json)。

[assignment完整映射](../results/full_mapping_assignment.bin)、[cumulative完整映射](../results/full_mapping_cumulative.bin)各262144字节，形状1024×256，偏移 `key*256+plaintext` 为密文；证据脚本由完整映射重新计数分桶、重组等价类并核对分析函数。

下图GUI固定明文为 `10101010`，与本节统计表的 `10011010` 不同，桶计数不能混用。

![固定明文的全部密文分组](../artifacts/gui/07_collision.png)

## 7. 本轮代码整理与证据审核

| 整理项 | 当前行为及验证 |
|---|---|
| 核心接口 | 公开并覆盖 `permute` 的数值、位宽、位置、空表边界；轨迹拒绝非布尔解密标志 |
| 攻击输入 | 先收集并验证迭代器，拒绝空迭代器及非法对，避免空输入匹配全部钥 |
| GUI旧结果 | 新ASCII/破解/碰撞输入失败时撤下旧结果及成功状态 |
| GUI线程状态 | 运行期间冻结输入和操作，拒绝重复启动；失败后结束计时并恢复控件，允许重试 |
| 交换报告 | 非法输入写失败报告及逐行错误；拒绝输入输出同一路径 |
| 自动证据 | 必须发现全域测试，全部测试成功且无跳过；动态记录全部模块/脚本/测试摘要 |
| 哈希审核 | 核15个计算来源、21个结果、5个GUI来源、10个静态截图及测试计数/名称 |

摘要分别保存在[计算证据清单](../results/evidence_manifest.json)与GUI清单。只读审核发现旧清单、源码或证据变化时提示重生成，测试数量不再写死。审核通过仅表示材料内部一致，不能证明真实外组互测已经发生，不能代替提交填表。

## 8. 42项测试及26项捕获检查

以下完整ID与 `unit_tests.json.test_names` 一一对应，每项通过：核心20项、分析10项、交换7项、GUI状态回归5项。5项GUI回归已计入42项，另有捕获脚本的26项控件检查。

| 序号 | 测试ID |
|---:|---|
| 1 | `tests.test_analysis_tools.AnalysisTests.test_all_plaintext_scan_retains_consistent_histograms_and_progress` |
| 2 | `tests.test_analysis_tools.AnalysisTests.test_attack_records_timezone_aware_timestamps_and_real_elapsed_time` |
| 3 | `tests.test_analysis_tools.AnalysisTests.test_collision_bad_plaintext_rejected` |
| 4 | `tests.test_analysis_tools.AnalysisTests.test_collision_buckets_really_partition_all_keys` |
| 5 | `tests.test_analysis_tools.AnalysisTests.test_empty_or_invalid_pairs_rejected` |
| 6 | `tests.test_analysis_tools.AnalysisTests.test_full_mapping_equivalence_matches_complete_known_plaintext_attack` |
| 7 | `tests.test_analysis_tools.AnalysisTests.test_inconsistent_pairs_produce_zero_candidates` |
| 8 | `tests.test_analysis_tools.AnalysisTests.test_pair_iterators_are_validated_before_search` |
| 9 | `tests.test_analysis_tools.AnalysisTests.test_progress_covers_all_keys` |
| 10 | `tests.test_analysis_tools.AnalysisTests.test_single_and_multiple_pairs_keep_true_key` |
| 11 | `tests.test_exchange.ExchangeScriptTests.test_csv_vectors_match_string_implementation` |
| 12 | `tests.test_exchange.ExchangeScriptTests.test_invalid_input_replaces_previous_successful_report` |
| 13 | `tests.test_exchange.ExchangeScriptTests.test_invalid_json_structure_is_reported` |
| 14 | `tests.test_exchange.ExchangeScriptTests.test_json_vectors_match_integer_implementation` |
| 15 | `tests.test_exchange.ExchangeScriptTests.test_malformed_bits_are_rejected` |
| 16 | `tests.test_exchange.ExchangeScriptTests.test_output_cannot_overwrite_supplied_vectors` |
| 17 | `tests.test_exchange.ExchangeScriptTests.test_wrong_ciphertext_is_reported` |
| 18 | `tests.test_gui.GuiStateTests.test_bad_ascii_input_replaces_successful_count` |
| 19 | `tests.test_gui.GuiStateTests.test_bad_collision_input_removes_previous_report` |
| 20 | `tests.test_gui.GuiStateTests.test_bad_pairs_remove_previous_successful_report` |
| 21 | `tests.test_gui.GuiStateTests.test_running_task_freezes_inputs_and_rejects_duplicate_start` |
| 22 | `tests.test_gui.GuiStateTests.test_worker_failure_finishes_timing_and_restores_controls` |
| 23 | `tests.test_sdes.ByteAndAsciiTests.test_all_128_ascii_characters` |
| 24 | `tests.test_sdes.ByteAndAsciiTests.test_all_256_bytes` |
| 25 | `tests.test_sdes.ByteAndAsciiTests.test_decrypting_non_ascii_bytes_rejected` |
| 26 | `tests.test_sdes.ByteAndAsciiTests.test_empty_and_control_and_normal_strings` |
| 27 | `tests.test_sdes.ByteAndAsciiTests.test_non_ascii_rejected` |
| 28 | `tests.test_sdes.CrossImplementationTests.test_all_subkeys_for_both_schedules` |
| 29 | `tests.test_sdes.ExhaustiveDomainTests.test_both_schedules_all_keys_all_blocks_and_bijections` |
| 30 | `tests.test_sdes.HandVectorTests.test_assignment_hand_round_trace` |
| 31 | `tests.test_sdes.HandVectorTests.test_decryption_trace_uses_reversed_keys` |
| 32 | `tests.test_sdes.HandVectorTests.test_default_schedule_is_assignment` |
| 33 | `tests.test_sdes.HandVectorTests.test_fixed_subkeys_and_ciphertexts` |
| 34 | `tests.test_sdes.InputValidationTests.test_binary_input_preserves_leading_zeros` |
| 35 | `tests.test_sdes.InputValidationTests.test_binary_input_rejects_invalid_values` |
| 36 | `tests.test_sdes.InputValidationTests.test_bytes_and_text_types_are_strict` |
| 37 | `tests.test_sdes.InputValidationTests.test_invalid_blocks` |
| 38 | `tests.test_sdes.InputValidationTests.test_invalid_keys` |
| 39 | `tests.test_sdes.InputValidationTests.test_invalid_widths` |
| 40 | `tests.test_sdes.InputValidationTests.test_permutation_validates_values_widths_and_positions` |
| 41 | `tests.test_sdes.InputValidationTests.test_trace_rejects_non_boolean_decrypt_flags` |
| 42 | `tests.test_sdes.InputValidationTests.test_unknown_schedule` |

26项捕获检查按清单序号覆盖以下操作，与上述错误状态和线程控制回归分别保存。

| 清单序号 | 捕获检查内容 |
|---|---|
| 1–3 | 默认位串加密、中间轨迹可见、解密还原 |
| 4–6 | ASCII Hex无字节丢失、Hex往返、Base64往返 |
| 7–11 | 单对/多对worker成功、全部候选可见、真实计时、同时满足全部输入对 |
| 12–14 | 碰撞worker成功、桶覆盖1024钥、存在不同钥同密文 |
| 15–21 | 非法位串/密钥、非ASCII、非法Base64与Hex拒绝 |
| 22–23 | 空明密文对及非法对拒绝 |
| 24–26 | 调度同步并清除旧结果、cumulative加密及往返 |

## 9. 复现与提交边界

在本实验的 `exp1/` 目录（README所在目录）运行以下命令；新运行记录新时间，旧计时不代表其他机器性能。GUI捕获由Qt控件事件和 `QWidget.grab()`完成，offscreen检查不等同于已人工验证所有桌面环境。

```powershell
python scripts/run_evidence.py
python scripts/capture_gui.py
python scripts/audit_submission.py
```

[开发手册](developer_manual.md)与[使用指南](user_guide.md)说明模块、API、入口和格式。原始JSON/CSV/完整映射、10张静态截图和任务计时记录均保留；修改源码或证据后须更新对应生成记录。

提交前仍需补齐实际两名成员身份与分工、真实外组互测及作业表中的仓库链接。S-DES的8位分组、10位密钥和逐字节独立模式用于教学，会暴露重复字节，不适合保护真实敏感信息。
