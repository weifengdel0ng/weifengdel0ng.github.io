+++
title = "深海金库"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


### Mobile-深海金库

**解题思路**
============

初步分析
========

解压 APK 后可以定位到两层核心逻辑：Java 层负责输入格式校验与字节预处理，Native 层负责最终验签。关键文件如下：

-   \`classes.dex\` / \`classes2.dex\` — Java 层逻辑

-   \`lib/x86_64/libsecure_verify.so\` — Native 校验

字符串搜索可见 \`com/example/mobile02/MainActivity\`、\`nativeVerify\`、\`libsecure_verify.so\`，可以确认真正的核心校验位于 Native 层。

Java 层流程
===========

交互坑点：长按触发
------------------

普通点击按钮只会弹出 \`Initializing Secure Handshake...\`，随后显示 \`Signature Error\`。真正的验 flag 逻辑位于 \`SecurityCoreProcessor.onLongClick\`，必须长按按钮才会进入 \`FlagValidator.doFinalCheck\`。

FlagValidator.isFormatValid
---------------------------

> if-eqz v1, \$false # null check
>
> const-string v0, "ISCC{"
>
> invoke-virtual startsWith # 必须以 ISCC{ 开头
>
> if-eqz v0, \$false
>
> const-string v0, "}"
>
> invoke-virtual endsWith # 必须以 } 结尾
>
> if-eqz v1, \$false
>
> const/4 v1, \#1 # return true

FlagValidator.doFinalCheck
--------------------------

> invoke-virtual length # 取输入长度
>
> add-int/lit8 v0, v0, \#-1 # length - 1
>
> const/4 v1, \#5
>
> invoke-virtual substring(5, length-1) # 去掉 ISCC{ 和 }
>
> invoke-static CryptoEngine.performTransformation # 转换
>
> invoke-virtual MainActivity.nativeVerify # 传入 native
>
> move-result v2
>
> return v2

CryptoEngine.performTransformation
----------------------------------

核心变换逻辑如下：

> byte[] b = input.getBytes(StandardCharsets.US_ASCII);
>
> int prev = 0;
>
> for (int i = 0; i &lt; b.length; i++) {
>
> int x = b[i] & 0xff;
>
> if (32 &lt;= x && x &lt;= 126) {
>
> x = ((x - 25) % 95) + 32; // printable 字符移位
>
> }
>
> int shift = (i % 2 == 0) ? 8 : -8; // 奇偶交替 ±8
>
> x = (x + shift + (prev % 4)) & 0xff;
>
> b[i] = (byte)x;
>
> prev = x; // 状态传递
>
> }
>
> return b;

-   先做 printable ASCII 范围内的旋转 \`((x - 25) % 95) + 32\`

-   然后加上位置相关 \`shift\`（偶数位 +8，奇数位 -8）以及 \`prev % 4\`

-   \`prev\` 取前一个输出字节，说明该变换存在状态依赖

CryptoEngine.getCheckSum
------------------------

> return b.length % 15;

这是一个辅助校验函数，实际主流程中并未直接参与最终 flag 校验。

Native 层分析
=============

JNI 桥 (\`verify_bridge\` @ 0x21160)
-------------------------------------

-   从 \`jbyteArray\` 获取 \`byte[]\` 指针与长度

-   调用 \`SV::v(data, length)\`

-   返回布尔结果给 Java 层

SV::v (@ 0x215f0)
-----------------

-   拷贝输入数据

-   调用 \`process_fib_stream(data, length)\`，执行斐波那契 XOR

-   调用 \`encode_b64(result)\`，做自定义 base64 编码

-   与目标字符串比较，相等则返回 \`true\`

process_fib_stream (@ 0x214f0)
--------------------------------

4 字节展开的斐波那契 XOR 逻辑如下：

> a = 1; b = 1;
>
> while (length &gt;= 4) {
>
> data[i+0] \^= a;
>
> data[i+1] \^= b;
>
> a += b; // new_a
>
> data[i+2] \^= a;
>
> b += a; // new_b
>
> data[i+3] \^= b;
>
> a += b; // next_a
>
> b += a; // next_b
>
> i += 4; length -= 4;
>
> }
>
> while (length &gt; 0) {
>
> data[i] \^= a;
>
> c = a + b;
>
> a = b;
>
> b = c;
>
> i++; length--;
>
> }

针对 18 字节输入，可以得到对应的 8-bit XOR 序列：

> [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 121, 98, 219, 61, 24]

encode_b64 (@ 0x21260)
-----------------------

编码流程本质上仍是标准 base64 的 3 字节到 4 字符映射，只是替换了字母表。自定义字母表位于 \`.rodata\` @ \`0x14e96\`：

> zKJUExRaVtM3Ydv5TQIsWD1frnHC78Lckl6euPh9AGoj0SgN4Zp+OwXi2F/ybmBq

填充字符 \`=\` 保持不变。

目标串构造
----------

-   先在栈上写入 12 字节：\`cUdltutGeWWI\`

-   再拼接 \`.rodata\` @ \`0x149b5\` 处的 12 字节：\`Um+7OE4ce3wi\`

最终比较的完整目标串为：

> cUdltutGeWWIUm+7OE4ce3wi

逆向求解
========

整体逆向过程可以拆成三步：先逆自定义 base64，再逆斐波那契 XOR，最后逆 Java 层状态变换。

1. 自定义 Base64 解码
---------------------

> custom = 'zKJUExRaVtM3Ydv5TQIsWD1frnHC78Lckl6euPh9AGoj0SgN4Zp+OwXi2F/ybmBq'
>
> standard = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
>
> trans = str.maketrans(custom, standard)
>
> encoded = 'cUdltutGeWWIUm+7OE4ce3wi'
>
> std_encoded = encoded.translate(trans)
>
> decoded = base64.b64decode(std_encoded)
>
> # -&gt; [124, 51, 97, 38, 66, 105, 141, 69, 18, 15, 220, 220, 208, 76, 31, 140, 189, 119]

2. 逆 process_fib_stream
--------------------------

由于 XOR 是自身的逆运算，只需要对解码结果使用同一组斐波那契序列再异或一次：

> fib = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 121, 98, 219, 61, 24]
>
> xored = bytes(d \^ f for d, f in zip(decoded, fib))
>
> # -&gt; [125, 50, 99, 37, 71, 97, 128, 80, 48, 56, 133, 76, 57, 53, 125, 87, 128, 111]

3. 逆 performTransformation
---------------------------

由于 \`performTransformation\` 存在 \`prev\` 状态依赖，最直接的做法是逐字节枚举 printable ASCII，找到能命中目标输出的原字符：

> def reverse_transform(expected):
>
> for c in range(32, 127):
>
> x = c
>
> if 32 &lt;= x &lt;= 126:
>
> x = ((x - 25) % 95) + 32
>
> shift = 8 if (i % 2 == 0) else -8
>
> x = (x + shift + (prev % 4)) & 0xFF
>
> if x == expected[i]:
>
> return chr(c)

求解得到的内部字符串为：

> n2R\#7_pQ!9vL*5mWnp

Flag

Exp

\#!/usr/bin/env python3\
import base64\
\
# 自定义 Base64 字母表\
CUSTOM_ALPHABET = "zKJUExRaVtM3Ydv5TQIsWD1frnHC78Lckl6euPh9AGoj0SgN4Zp+OwXi2F/ybmBq"\
STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"\
TARGET_B64 = "cUdltutGeWWIUm+7OE4ce3wi"\
\
\
def custom_b64decode(encoded: str) -&gt; bytes:\
*"""使用自定义字母表将 Base64 字符串还原为字节流。"""\
*trans = str.maketrans(CUSTOM_ALPHABET, STD_ALPHABET)\
std = encoded.translate(trans)\
return base64.b64decode(std)\
\
\
def process_fib_stream(data: bytes) -&gt; bytes:\
*"""按斐波那契序列低 8 位对数据逐字节 XOR。"""\
*a, b = 1, 1\
out = bytearray()\
for byte in data:\
out.append(byte \^ (a & 0xFF))\
a, b = b, (a + b) & 0xFF\
return bytes(out)\
\
\
def reverse_transform(expected: bytes) -&gt; str:\
*"""逆向还原 performTransformation 后的可打印 ASCII 字符串。"""\
*result = []\
prev = 0\
\
for i, target in enumerate(expected):\
matched = False\
for c in range(32, 127):\
x = c\
x = ((x - 25) % 95) + 32\
shift = 8 if i % 2 == 0 else -8\
x = (x + shift + (prev % 4)) & 0xFF\
\
if x == target:\
result.append(chr(c))\
prev = target\
matched = True\
break\
\
if not matched:\
raise ValueError(f"无法还原第 {i} 个字节: {target:\#x}")\
\
return "".join(result)\
\
\
def solve() -&gt; str:\
decoded = custom_b64decode(TARGET_B64)\
xored = process_fib_stream(decoded)\
inner = reverse_transform(xored)\
return f"ISCC{{{inner}}}"\
\
\
def main() -&gt; None:\
print(solve())\
\
\
if __name__ == "__main__":\
main()
