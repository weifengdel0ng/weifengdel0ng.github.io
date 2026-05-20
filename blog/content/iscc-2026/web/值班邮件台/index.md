+++
title = "值班邮件台"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Web + 值班邮件台

解题思路：

题目首页是一个“值班邮件台”系统，访问后可以在响应中发现两个与身份相关的 Cookie，分别是 \`mail\_user=guest\` 和 \`mail\_role=user\`。同时页面内容还提示前端继续沿用浏览器侧的旧标记做身份切换联调，这说明后台很可能直接信任客户端传入的身份字段，没有做真正的服务端鉴权绑定。因此首先尝试伪造 Cookie，将其修改为 \`mail\_user=admin; mail\_role=admin\`，然后访问 \`/admin.php\`，成功进入后台预览面板。

进入后台后，页面给出了一个联调说明文件下载地址 \`/download.php?file=files/notes/preview-readme.txt\`。读取该文件后，得知预览器只能访问本机内部地址，并且真实的诊断路由映射记录在 \`route-index.txt\` 中。继续读取 \`/download.php?file=files/notes/route-index.txt\`，得到内部路由索引，其中 \`final\` 对应 \`/internal/report?view=flag&slot=last\`，这实际上已经给出了最终敏感接口的位置。

后台表单要求提交 \`token\_a\`、\`token\_b\` 和 \`target\_url\` 三个参数。结合题目中对“双人复核”的提示，可以推测服务端逻辑是要求两个 token 本身不能完全相同，但它们的摘要值必须相同。这很符合 PHP 中常见的弱比较问题，例如通过 \`md5(\$a) == md5(\$b)\` 进行判断。于是使用经典魔术哈希绕过数据 \`QNKCDZO\` 和 \`240610708\`，它们的 MD5 值都表现为 \`0e...\` 形式，在 PHP 弱比较下会被当作数字 0，从而判定相等，成功绕过复核逻辑。

最后将 \`target\_url\` 设置为本机完整地址 \`http://127.0.0.1/internal/report?view=flag&slot=last\`，向后台提交请求。由于后台具备本机访问能力，最终成功读取到内部诊断结果中的 flag。

本题核心漏洞链为：客户端 Cookie 伪造身份 → 联调文件泄露内部路由 → PHP 弱比较绕过复核 → 后台 SSRF 访问本地敏感接口。

Exp：

\`\`\`python

import requests

url = "http://39.105.213.28:49103/admin.php"

cookies = {

"mail\_user": "admin",

"mail\_role": "admin",

}

data = {

"token\_a": "QNKCDZO",

"token\_b": "240610708",

"target\_url": "http://127.0.0.1/internal/report?view=flag&slot=last",

}

r = requests.post(url, cookies=cookies, data=data)

print(r.text)

\`\`\`

Flag：

\`ISCC{ACxmCnWgL3C7LqWImKfgtK6h}\`
