+++
title = "迷雾验证"
date = "2026-05-06"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++
**WP**
APK 先用 `apktool d` 解包，入口在 `com.example.mobile01.MainActivity`。点击按钮后逻辑在 `MainActivity$1.onClick()`：

```java
input = etFlagInput.getText().toString().trim();

if (!FlagFormatChecker.checkBasicFormat(input)) {
    wrong;
    return;
}

if (FlagDispatcher.dispatchCheck(input)) {
    success;
} else {
    wrong;
}
```

`FlagFormatChecker` 只检查格式：

```text
ISCC{...}
```

真正校验在：

```java
LocalExecutor.verify(input)
```

对应 native 库：

```text
libmobile01.so
```

Native 导出符号里能看到关键函数：

```text
Java_com_example_mobile01_LocalExecutor_verify
encrypt_full
custom_base64_encode
rc4
xor_encrypt
to_hex
build_keyed_b64_table
get_rc4_key
get_xor_key
get_b64_key_from_java
```

Java 层还有 `KeyProvider.a1()`，它读取 `assets/bin.data`，用 AES/CBC/PKCS7 解密：

```text
AES key = 1234567890abcdef
AES iv  = abcdef1234567890
```

解密得到：

```text
key-456-xyz
```

这个值用于生成自定义 Base64 表。标准 Base64 表按字符 ASCII 和取模旋转：

```python
base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
rot = sum(map(ord, "key-456-xyz")) % 64
table = base[rot:] + base[:rot]
```

`rot = 45`，所以自定义表为：

```text
tuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs
```

Native 目标串为：

```text
4TyqGS1d9262e3ff6f8122230261f
```

`encrypt_full` 会把 `ISCC{}` 中间内容拆成三段：

```text
part1: 前 5 字节
part2: 接下来 6 字节
part3: 剩余 5 字节
```

分别处理：

```text
part1 -> custom_base64_encode
part2 -> rc4 -> hex
part3 -> xor_encrypt -> hex
```

还原出的 key：

```text
RC4 key = jihgfedcba
XOR key = wxy`ab012
```

求解脚本：

```python
import base64

target = "4TyqGS1d9262e3ff6f8122230261f"

seg1 = target[:7]
seg2 = target[7:19]
seg3 = target[19:]

std_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
java_key = "key-456-xyz"

rot = sum(map(ord, java_key)) % 64
custom_b64 = std_b64[rot:] + std_b64[:rot]

rc4_key = b"jihgfedcba"
xor_key = b"wxy`ab012"

def rc4(data, key):
    s = list(range(256))
    j = 0

    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    out = bytearray()

    for b in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xff])

    return bytes(out)

def xor_dec(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def custom_b64_decode(s):
    trans = str.maketrans(custom_b64, std_b64)
    std = s.translate(trans)
    std += "=" * ((4 - len(std) % 4) % 4)
    return base64.b64decode(std)

p1 = custom_b64_decode(seg1)
p2 = rc4(bytes.fromhex(seg2), rc4_key)
p3 = xor_dec(bytes.fromhex(seg3), xor_key)

flag = "ISCC{" + (p1 + p2 + p3).decode("latin1") + "}"
print(flag)
```

输出：

```text
ISCC{.a}fR;E":3PeZIF~}
```

最终 flag：

```text
ISCC{.a}fR;E":3PeZIF~}
```
## 附件下载

- [attachment-8.apk](attachment-8.apk)

