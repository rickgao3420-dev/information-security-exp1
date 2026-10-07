# 信息安全导论 · 实验一：S-DES

使用 **Python + PyQt5** 实现 8 位分组、10 位密钥的 S-DES，包括 GUI 加解密、ASCII 扩展、已知明密文穷举和密钥碰撞分析。GUI 与 CLI 共用算法核心，置换、循环移位、异或、S 盒和两轮 Feistel 计算均自行实现。

作业依据：[石墨《作业1：S-DES算法实现》](https://shimo.im/docs/m5kvdlMaKvcENy3X)。公开仓库：[information-security-exp1](https://github.com/rickgao3420-dev/information-security-exp1)。

**核对结论：第 1、2、3、5 关已实现并验证；第 2 关已与同学小组使用作业示例明文、密文和密钥完成交叉核对，并通过本机独立实现对照。第 4 关实现与计算验证通过，保留静态截图和计时记录。**

## 五项过关要求核对

| 关卡 | 作业要求摘要 | 实现与证据 | 核对结果 |
| --- | --- | --- | --- |
| 第 1 关：基本测试 | GUI 输入 8 位数据和 10 位密钥，输出 8 位密文，支持加解密 | [核心](sdes.py)、[GUI](gui.py)；手算向量、两种调度全域验证、加解密截图 | 已实现并验证 |
| 第 2 关：交叉测试 | 两组按相同算法参数核对同一组明密文，并检查加密结果或互相解密结果 | 与同学小组使用作业示例明文、密文和密钥完成核对；另有[独立参考实现](reference_sdes.py)、[交换向量](results/cross_vectors.json)及[比较工具](scripts/compare_cross_vectors.py)，本机共 524,288 个组合对照 | 已实现并完成小组交叉验证 |
| 第 3 关：扩展功能 | ASCII 字符串按 1 Byte 分组加解密 | ASCII API，GUI/CLI 的 Hex、Base64 密文表示；ASCII 0–127、字节 0–255 与空串往返 | 已实现并验证 |
| 第 4 关：暴力破解 | 从一对或多对已知明密文穷举密钥，设定时间戳，用视频或动图展示耗时 | [穷举模块](analysis_tools.py)、GUI 后台线程；检查全部 1024 钥、报告全部候选、真实计时和静态截图 | 实现与计算验证通过；动态演示证据未保留 |
| 第 5 关：封闭测试 | 分析一对明密文的多个候选，以及不同密钥对给定明文产生相同密文的情况 | 固定明文分桶、全部 256 明文扫描、完整置换等价分析；[碰撞与等价证据](results/) | 已实现并验证 |

逐关输入、结果、截图和局限见 [测试报告](docs/test_report.md)；算法参数及需求边界见 [要求核对](docs/requirements.md)。TCP 通信和多线程加速是题目提出的拓展选择；本项目 GUI 使用后台线程保持响应。

## 快速开始

需要 **Python 3.10+**。在 GitHub 克隆的仓库根目录运行：

```powershell
cd exp1
python -m pip install -r requirements.txt
python gui.py
```

如果当前已经是本 README 所在目录，省略 `cd exp1`。GUI 提供“8 位加解密”“ASCII 字符串”“暴力破解”“密钥碰撞”四个标签页。顶部选择的调度作用于全部操作，详细步骤见 [用户指南](docs/user_guide.md)。

核心、CLI 和不涉及 GUI 的测试只使用 Python 标准库；PyQt5 用于界面与截图。

### CLI 示例

以下命令在本 README 所在目录执行，默认使用 `assignment`。

```powershell
# 第 1 关：输出 11101111，再解密还原 10011010
python cli.py bits encrypt 10011010 --key 1010000010
python cli.py bits decrypt 11101111 --key 1010000010
# 查看逐轮中间结果
python cli.py bits encrypt 10011010 --key 1010000010 --trace

# 第 3 关：输出 E45C8989ABC2CB9B30CBAD，再还原原文
python cli.py ascii encode 'Hello SDES!' --key 1010000010 --format hex
python cli.py ascii decode E45C8989ABC2CB9B30CBAD --key 1010000010 --format hex

# 第 4 关：单对 4 个候选；增加第二对后 2 个候选
python cli.py attack --pair 10101010:00001001
python cli.py attack --pair 10101010:00001001 --pair 00000000:01101010

# 第 5 关：固定明文碰撞、全明文扫描、全局等价分析
python cli.py collision --plaintext 10101010
python cli.py collision --all
python cli.py collision --equivalent
```

位串必须保留前导零：分组恰好 8 位，密钥恰好 10 位。ASCII 明文范围为 0–127；密文字节可能不可打印，用 Hex/Base64 表示并按相同格式解码。更多选项用 `python cli.py --help` 查看。

## 算法参数与密钥调度

置换表和 S 盒采用作业 §2 的值，尤其使用**作业修改后的 S-box2**，全部常量见 [sdes.py](sdes.py) 和 [参数说明](docs/requirements.md)。第二轮后直接执行逆初始置换，解密将子密钥次序反转。

作业公式为 `K_i = P8(Shift^i(P10(K))), i=1,2`；课件流程先 LS1，再额外 LS2。项目保留两种明确标注的解释：

| 调度 | K1、K2 相对 P10 后原始半块的总左移量 | 使用方式 |
| --- | --- | --- |
| `assignment`（默认） | 1、2 位 | 按作业公式字面解释 |
| `cumulative` | 1、3 位 | 兼容课件累计移位流程 |

密钥 `1010000010`、明文 `10011010` 在两种模式下的密文分别为 `11101111`、`01101011`。CLI 添加 `--schedule cumulative` 切换，GUI 使用顶部下拉框切换。加密、解密、攻击和跨组向量必须使用相同模式。

## 破解与碰撞结论

默认调度下，固定任一明文遍历 1024 钥得到 **254 种密文**，最大碰撞桶含 **8 个密钥**；全部密钥对应 **512 种完整加密置换**，每个等价类恰好含两个密钥。

原因是默认调度的 K1/K2 都没有选中原始主密钥从左起第 2 位。`1010000010` 与 `1110000010` 对全部 256 个明文完全等价，所以增加已知明密文对也无法唯一恢复这一位。兼容调度完整扫描得到 1024 种不同置换，没有全局等价钥。

固定明文有 1024 个密钥、最多 256 种密文，必然存在碰撞。**单个明文上的碰撞不等于全局等价**；判等价必须比较全部 256 个明文的映射。本项目保存完整映射及碰撞但不等价的反例，见 [测试报告](docs/test_report.md)。

暴力破解的静态截图与实际开始/结束时间、计算耗时见 [GUI 捕获清单](artifacts/gui/capture_manifest.json)。动态演示已删除，当前材料不包含第 4 关要求的视频或动图证据。

## 代码与交付材料

```text
exp1/
├── sdes.py                 # 核心、ASCII/字节 API、逐轮轨迹
├── analysis_tools.py       # 穷举、碰撞、全明文扫描、等价密钥
├── reference_sdes.py       # 独立的字符串参考实现
├── gui.py                  # PyQt5 界面与后台线程
├── cli.py                  # 命令行入口
├── requirements.txt        # GUI 与截图依赖
├── tests/                  # 算法、分析、交换与界面回归测试
├── scripts/                # 证据生成、GUI 捕获、向量比较、材料审核
├── docs/                   # 需求、用户指南、开发手册、逐关报告
├── results/                # JSON/CSV、日志、完整映射与哈希
└── artifacts/gui/          # 静态截图与捕获清单
```

| 提交条目 | 对应材料 |
| --- | --- |
| §5.2.1 源代码 | 核心、分析、界面、CLI、参考实现、测试及脚本 |
| §5.2.2 五关测试结果 | [逐关报告](docs/test_report.md)、[计算汇总](results/summary.json)、[静态截图](artifacts/gui/) |
| §5.2.3 相关文档 | [用户指南](docs/user_guide.md)、[开发手册及 API](docs/developer_manual.md)、[要求与参数](docs/requirements.md) |

## 复现与审核

```powershell
# 所有单元测试，含两种调度完整的 1024 × 256 输入空间
python -m unittest discover -s tests -v
# 重跑测试并生成五关计算证据
python scripts/run_evidence.py
# 操作真实 Qt 控件，重新生成静态截图与检查记录
python scripts/capture_gui.py
# 只读核对链接、记录、源码及证据文件摘要
python scripts/audit_submission.py
```

两个生成脚本会覆盖各自生成文件，保存实际环境、时间和 SHA-256。测试数量见 [unit_tests.json](results/unit_tests.json)，GUI 检查见捕获清单。全域对照覆盖 **524,288** 个“调度、密钥、明文”组合，同时验证双方解密和 **2,048** 个固定密钥映射均为双射。

本轮重新验证：**42 项单元测试全部通过**（其中 5 项为 GUI 状态回归），另有 **26 项 Qt 控件与捕获检查通过**，保存 10 张功能截图。

本次代码整理补齐置换 API 的输入校验，拒绝空破解迭代器，简化碰撞统计；修复 GUI 错误输入残留旧结果及后台任务状态问题；交换文件无效时明确生成失败报告，并将结果和截图纳入 SHA-256 审核。

S-DES 为教学算法；本项目逐字节独立加密，不用于保护实际敏感数据。
