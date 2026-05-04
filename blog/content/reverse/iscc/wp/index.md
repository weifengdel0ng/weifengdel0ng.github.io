+++
title = "iscc"
date = "2026-05-03"
type = "post"
categories = ["Reverse"]
tags = ["Reverse"]
draft = false
+++
在字符串里可以直接看到目标比较值：

```text
000A9CD32B9E4D0D563A190E6B2DC2923ADA53F5BEF22A7A
```

主逻辑里一共用了 4 个数字：

```text
344, 21, 89, 233
```

对 `{}` 内的内容依次进行：

1. `RC4(key="344")`
2. 与 `"21"` 循环异或
3. 与 `"89"` 循环逐字节相加
4. 用 `SHA256("233")` 的前 16 字节作为 TEA key 加密
5. 转大写十六进制后与目标常量比较

因此只需要逆向还原：

1. 目标 hex 转字节
2. TEA 解密
3. 去填充
4. 循环减去 `"89"`
5. 循环异或 `"21"`
6. RC4 解密，key=`"344"`

还原后得到明文：

```text
deaIoihuwuasyIleolyclrt
```

所以最终 flag 为：

```text
ISCC{deaIoihuwuasyIleolyclrt}
```
