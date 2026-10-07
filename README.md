# 信息安全导论 · 实验一：S-DES

使用 Python + PyQt5 完成作业要求的 S-DES 加解密、ASCII、穷举破解与碰撞分析。全部源码和材料位于 [`exp1/`](exp1/)，完整说明见 [实验首页](exp1/README.md)。

| 提交条目 | 内容 |
| --- | --- |
| 5.2.1 源代码 | [核心](exp1/sdes.py)、[GUI](exp1/gui.py)、[CLI](exp1/cli.py)、[分析](exp1/analysis_tools.py)、[独立参考实现](exp1/reference_sdes.py)、[测试](exp1/tests/) |
| 5.2.2 五关测试结果 | [测试报告](exp1/docs/test_report.md)、[JSON/CSV 计算证据](exp1/results/)、[GUI 截图与破解 GIF](exp1/artifacts/gui/) |
| 5.2.3 相关文档 | [用户指南](exp1/docs/user_guide.md)、[开发手册与接口文档](exp1/docs/developer_manual.md)、[要求及参数](exp1/docs/requirements.md) |

```sh
cd exp1
python -m pip install -r requirements.txt
python gui.py
```

29 项算法测试和 26 项 GUI 检查通过；两种密钥调度共 524,288 个输入完成独立实现比对及双向解密核验。

**真实组间与异构平台测试尚未进行**：目前已完成本机两份独立实现对照，提供 JSON/CSV 交换向量与比较工具，等待另一组程序。作业公式与课件累计移位有歧义，默认 `assignment` 使用总移 1、2 位，`cumulative` 兼容总移 1、3 位；参数差异及等价密钥结论均在文档中明确记录。

![真实破解 GUI 动图](exp1/artifacts/gui/brute_force_actual.gif)

动图播放 12.7 秒供阅读，实测破解约 0.00434 秒；具体时间戳见捕获清单。课程原始 PPT/PDF 未修改，未包含在仓库中。
