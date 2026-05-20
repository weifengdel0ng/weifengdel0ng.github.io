+++
title = "灵感笔记"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Web + 灵感笔记

解题思路：

题目是一个 Flask 云笔记应用，所有数据都存储在 Session 中，没有使用数据库。首先在前端 \`main.js\` 中发现了两个关键接口，一个是 \`POST /api/v1/project/detail\`，可通过 \`project_id\` 获取项目详情；另一个是 \`GET /api/admin/hint\`，只有管理员可以访问。继续分析后确认 Session 中保存了用户信息、笔记内容、日志、注册用户等数据，说明整个系统高度依赖服务端 Session 逻辑。

接着尝试登录后台，发现管理员存在弱口令 \`admin/admin\`，成功登录后访问 \`/api/admin/hint\`，得到隐藏接口 \`POST /api/v1/project/detail\` 的调用提示。根据管理员账户下的内容，发现存在 \`flag-project-001\` 这一敏感笔记。随后直接向 \`/api/v1/project/detail\` 提交该 \`project_id\`，虽然接口返回了 \`403 Forbidden\`，但同时返回了一个 \`trace_id\`。

进一步利用 \`POST /feedback\` 并提交这个 \`trace_id\`，成功查询到对应的错误日志。在日志中的 \`stack_trace\` 字段里发现了一段十六进制数据，经判断这是 Python 的 pickle 序列化内容。将其转为字节后使用 \`pickle.loads()\` 反序列化，最终从对象中的 \`flag\` 字段拿到目标内容。

本题的核心漏洞链为：弱口令登录管理员 → 越权访问接口（IDOR）→ 调试日志泄露敏感对象 → 反序列化提取 flag。

Exp：

```python

import pickle

hex_data = "80049591000000000000007d94288c0474797065948c0b464c41475f4f424a454354948c04666c6167948c24495343437b63347265667531315f64656275675f74723463655f6c33346b5f316430727d948c0a70726f6a6563745f6964948c10666c61672d70726f6a6563742d303031948c0974696d657374616d70948c1a323032362d30352d30395430353a30353a31"

data = bytes.fromhex(hex_data)

obj = pickle.loads(data)

print(obj["flag"])

```

Flag：

\`ISCC{c4refu11_debug_tr4ce_l34k_1d0r}\`
