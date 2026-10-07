# 信息安全导论 · 实验一：S-DES

Python + PyQt5 实现 8 位分组、10 位密钥的 S-DES。完整代码、运行说明和逐关核对见 [实验 README](exp1/README.md)，作业来源为[石墨文档](https://shimo.im/docs/m5kvdlMaKvcENy3X)。

| 关卡 | 当前状态 |
| --- | --- |
| 第 1 关：基本测试 | GUI 加解密、严格输入校验及完整域验证通过 |
| 第 2 关：交叉测试 | 已与同学小组使用作业示例明文、密文和密钥完成交叉核对；本机两份独立实现对照通过 |
| 第 3 关：扩展功能 | ASCII 逐字节加解密，Hex/Base64 表示与往返验证通过 |
| 第 4 关：暴力破解 | 全部 1024 钥穷举、单对/多对候选和真实计时通过；当前仅保留静态截图与计时记录 |
| 第 5 关：封闭测试 | 固定明文碰撞、全部明文扫描及全局等价密钥分析通过 |

```powershell
cd exp1
python -m pip install -r requirements.txt
python gui.py
```

本轮 42 项单元测试和 26 项 GUI 检查通过；两种密钥调度共 524,288 个输入组合完成独立实现比对及双向解密核验。默认 `assignment` 的总左移为 1、2 位；`cumulative` 兼容总左移 1、3 位，交叉核对时同步使用相同参数。

| 提交材料 | 文件 |
| --- | --- |
| 源代码 | [核心](exp1/sdes.py)、[GUI](exp1/gui.py)、[CLI](exp1/cli.py)、[分析](exp1/analysis_tools.py)、[独立参考实现](exp1/reference_sdes.py)、[测试](exp1/tests/) |
| 五关测试结果 | [逐关报告](exp1/docs/test_report.md)、[计算结果](exp1/results/)、[静态截图与计时清单](exp1/artifacts/gui/) |
| 相关文档 | [用户指南](exp1/docs/user_guide.md)、[开发手册与 API](exp1/docs/developer_manual.md)、[要求和参数](exp1/docs/requirements.md) |
