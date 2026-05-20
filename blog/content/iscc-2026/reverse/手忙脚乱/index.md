+++
title = "手忙脚乱"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

# ISCC2026 WriteUp


**题目类型**：Reverse

**题目名称**：手忙脚乱（新附件 attachment-62.exe）

---

## 解题思路

\### 1. 初步信息收集

拿到附件 \`attachment-62.exe\`，首先确认文件类型：

这是一个 64 位 Windows 控制台程序。通过 strings 提取关键字符串：

```

input 24 char plaintext:

len error

PASS

FAIL

transpose: length mismatch

```

以及关键函数符号：

```

decrypt_blob

columnarTransposeEncrypt

encryptPart2

makeTable

hdb3

```

这表明程序内部包含列换位加密、替换表加密和 HDB3 编码校验等操作。从符号名可以推断出多个加密常量以局部静态变量的形式存放。

\### 2. 定位加密常量

通过 objdump 反汇编，定位到 main 函数中 6 处 \`decrypt_blob\` 调用。这些调用各自引用一个局部静态常量，并传入不同的解密种子：

| 常量名 | 大小 | 种子 | .rdata 偏移 |

|--------|------|------|-------------|

| CT_K6 | 6 字节 | 0x5555 | 0x617b |

| CT_K3 | 3 字节 | 0x6666 | 0x6178 |

| CT_MASK1 | 24 字节 | 0x3333 | 0x6120 |

| CT_TARGET | 24 字节 | 0x1111 | 0x6160 |

| CT_MASK2 | 24 字节 | 0x4444 | 0x6100 |

| CT_TARGET_T | 24 字节 | 0x2222 | 0x6140 |

对应的汇编代码确认各常量大小（以 CT_MASK1 为例）：

```

mov \$0x3333,%r9d ; seed

mov \$0x18,%r8d ; size = 24

lea 0x28a8(%rip),%rdx ; → CT_MASK1

call decrypt_blob

```

从 PE 文件中按偏移提取原始密文字节。

\### 3. 还原 decrypt_blob 算法

\`decrypt_blob\` 内部基于一个自定义的流密码：状态变量通过乘法、移位和异或不断更新，每轮产生一个密钥字节与密文异或，再经过循环右移和最终异或得到明文。

还原后的 Python 实现核心逻辑为：

```python

def decrypt_blob(ct: bytes, seed: int) -&gt; bytes:

state = seed \^ 0xA3B1C2D3

acc = 0

ctr = 0

out = bytearray()

for b in ct:

x = (state + acc) & 0xFFFFFFFF

acc = (acc - 0x61C88647) & 0xFFFFFFFF

state = x

state \^= (state &lt;&lt; 13) & 0xFFFFFFFF

state \^= state &gt;&gt; 17

state \^= (state &lt;&lt; 5) & 0xFFFFFFFF

mix = (ctr + ((state * 8) & 0xFFFFFFFF) - state) & 0xFFFFFFFF

ctr = (ctr + 11) & 0xFFFFFFFF

v = (mix & 0xFF) \^ b

v = ror8(v, state &gt;&gt; 27)

v \^= state & 0xFF

out.append(v & 0xFF)

return bytes(out)

```

解密 6 个常量得到：

- K6 = \`B0\`o!*\`

- K3 = \`Re\$\`

- MASK1、TARGET、MASK2、TARGET_T 各为 24 字节的中间值

\### 4. 分析主校验流程

\`main\` 函数是一个两轮交互循环：

**第一轮**：读入 24 字节输入 → 用 \`columnarTransposeEncrypt(K6, K3)\` 的结果作为列换位 key 对输入做列换位 → 将结果送入 \`encryptPart2\`（基于 K6 的 bit 流驱动双表替换）→ 将输出与 MASK1 异或 → 与 TARGET 比较。通过后设置状态标志位，回到输入循环。

**第二轮**：相同的前置变换 → 输出与 MASK2 异或后再与 TARGET_T 异或 → 结果转为 bit 流做 HDB3 编码统计 → 与全零串的 HDB3 统计比较。若令 \`Buf2 = 0\`（即第二轮加密结果 = MASK2 xor TARGET_T），则 HDB3 统计自然相同，无需触及 HDB3 编码约束。

第一轮目标：

```

wanted1 = MASK1 xor TARGET

```

第二轮目标：

```

wanted2 = MASK2 xor TARGET_T

```

\### 5. 逆向构造输入

\`encryptPart2\` 可逆。其内部流程为：

1\. \`makeTable(key, 0x1234)\` 生成替换表 table0

2\. \`makeTable(key, 0x8888)\` 生成替换表 table1

3\. 遍历 key 的 bit 流，bit=0 用 table0 替换当前字符，bit=1 用 table1 替换；每满 24 字节做一次列换位

逆向时从后往前遍历 bit 流：在列换位边界处先逆列换位，再用逆向替换表还原字符。逆替换表直接对 table0/table1 建立 \`{密文字节: 原始偏移+0x20}\` 的映射。

再对 \`encryptPart2\` 的输出做逆列换位（使用 trans_key = columnarEncrypt(K6, K3) = \`\` \`*Bo0! \`\`），即得到原始 24 字节输入。

整体逆向链：

```

wanted → inverse encryptPart2 → inverse columnar transpose → plaintext

```

\### 6. 求解结果

运行脚本得到两行 24 字节明文：

```

第一轮（状态推进）：@"9w3Cv).e,'7&gt;khG-[Vg-0L

第二轮（最终校验）：R_0ElnXnl5d(u9q@(48MN\`d\`

```

向程序依次输入这两行，第二轮输出 \`PASS\`。

按 ISCC 平台提交格式包裹 flag：

```

ISCC{R_0ElnXnl5d(u9q@(48MN\`d\`}

```

---

## Exp

```python

\#!/usr/bin/env python3

from __future__ import annotations

def ror8(x: int, c: int) -&gt; int:

c &= 7

x &= 0xFF

if c == 0:

return x

return ((x &gt;&gt; c) | ((x &lt;&lt; (8 - c)) & 0xFF)) & 0xFF

def decrypt_blob(ct: bytes, seed: int) -&gt; bytes:

state = seed \^ 0xA3B1C2D3

acc = 0

ctr = 0

out = bytearray()

for b in ct:

x = (state + acc) & 0xFFFFFFFF

acc = (acc - 0x61C88647) & 0xFFFFFFFF

state = x

state \^= (state &lt;&lt; 13) & 0xFFFFFFFF

state \^= state &gt;&gt; 17

state \^= (state &lt;&lt; 5) & 0xFFFFFFFF

mix = (ctr + ((state * 8) & 0xFFFFFFFF) - state) & 0xFFFFFFFF

ctr = (ctr + 11) & 0xFFFFFFFF

v = (mix & 0xFF) \^ b

v = ror8(v, state &gt;&gt; 27)

v \^= state & 0xFF

out.append(v & 0xFF)

return bytes(out)

def make_table(key: bytes, seed: int) -&gt; bytes:

table = list(range(0x20, 0x7F))

state = seed & 0xFFFFFFFF

for b in key:

state = (state * 0x83 + b) & 0xFFFFFFFF

for i in range(94, 0, -1):

state = (state * 0x41C64E6D + 0x3039) & 0xFFFFFFFF

j = state % (i + 1)

table[i], table[j] = table[j], table[i]

return bytes(table)

def column_order(key: bytes) -&gt; list[int]:

return sorted(range(len(key)), key=lambda i: (key[i], i))

def columnar_encrypt(data: bytes, key: bytes) -&gt; bytes:

cols = len(key)

assert len(data) % cols == 0

rows = len(data) // cols

return bytes(data[r * cols + c] for c in column_order(key) for r in range(rows))

def columnar_decrypt(ct: bytes, key: bytes) -&gt; bytes:

cols = len(key)

assert len(ct) % cols == 0

rows = len(ct) // cols

grid = [[0] * cols for _ in range(rows)]

p = 0

for c in column_order(key):

for r in range(rows):

grid[r][c] = ct[p]

p += 1

return bytes(grid[r][c] for r in range(rows) for c in range(cols))

def to_bits(data: bytes) -&gt; list[int]:

return [(b &gt;&gt; shift) & 1 for b in data for shift in range(7, -1, -1)]

def encrypt_part2(data: bytes, key: bytes) -&gt; bytes:

table0 = make_table(key, 0x1234)

table1 = make_table(key, 0x8888)

s = bytearray(data)

pos = 0

for bit in to_bits(key):

s[pos] = (table1 if bit else table0)[s[pos] - 0x20]

pos += 1

if pos == len(s):

s = bytearray(columnar_encrypt(bytes(s), key))

pos = 0

return bytes(s)

def decrypt_part2(ct: bytes, key: bytes) -&gt; bytes:

table0 = make_table(key, 0x1234)

table1 = make_table(key, 0x8888)

inv0 = {c: i + 0x20 for i, c in enumerate(table0)}

inv1 = {c: i + 0x20 for i, c in enumerate(table1)}

s = bytes(ct)

bits = to_bits(key)

length = len(s)

for i in range(len(bits) - 1, -1, -1):

if (i + 1) % length == 0:

s = columnar_decrypt(s, key)

pos = i % length

arr = bytearray(s)

arr[pos] = (inv1 if bits[i] else inv0)[arr[pos]]

s = bytes(arr)

return s

def bxor(a: bytes, b: bytes) -&gt; bytes:

return bytes(x \^ y for x, y in zip(a, b))

# 从 attachment-62.exe 提取的密文常量

CT_K6 = bytes.fromhex("1855a378c86c")

CT_K3 = bytes.fromhex("67cedd")

CT_MASK1 = bytes.fromhex("4b5d1c5e410f506bed0c079a18b04c7c09c8d74957090771")

CT_TARGET = bytes.fromhex("8cad03aa6a32b926158f7c95eacadd159400412da55643ac")

CT_MASK2 = bytes.fromhex("cce7e28169d8ffcd64d27a929fbdb6105cb0137a67e78359")

CT_TARGET_T = bytes.fromhex("cce1a2150c88288ca52d9302724bd6b687512c9b7c4f4faa")

def main() -&gt; None:

k6 = decrypt_blob(CT_K6, 0x5555)

k3 = decrypt_blob(CT_K3, 0x6666)

trans_key = columnar_encrypt(k6, k3)

mask1 = decrypt_blob(CT_MASK1, 0x3333)

target1 = decrypt_blob(CT_TARGET, 0x1111)

wanted1 = bxor(mask1, target1)

mask2 = decrypt_blob(CT_MASK2, 0x4444)

target2 = decrypt_blob(CT_TARGET_T, 0x2222)

wanted2 = bxor(mask2, target2)

round1 = columnar_decrypt(decrypt_part2(wanted1, k6), trans_key)

round2 = columnar_decrypt(decrypt_part2(wanted2, k6), trans_key)

assert encrypt_part2(columnar_encrypt(round1, trans_key), k6) == wanted1

assert encrypt_part2(columnar_encrypt(round2, trans_key), k6) == wanted2

print(f"K6 = {k6.decode()}")

print(f"K3 = {k3.decode()}")

print(f"key = {trans_key.decode()}")

print(f"stage1 plaintext = {round1.decode()}")

print(f"final plaintext = {round2.decode()}")

print(f"submit = ISCC{{{round2.decode()}}}")

if __name__ == "__main__":

main()

```
