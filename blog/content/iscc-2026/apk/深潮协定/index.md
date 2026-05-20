+++
title = "深潮协定"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

### mobile+ 深潮协定

解题思路：

题目给出一个 Android APK，包名为 \`cn.iscc.deepseal\`，核心校验流程分为 Java 层和 Native 层两部分。首先在 Java 层分析 \`FlagValidator.check()\`，可以看到程序先检查输入是否满足 \`ISCC{}\` 的格式，然后取出花括号内部内容，交给 \`CryptoEngine.transform()\` 处理，最后再调用 \`NativeBridge.verify()\` 进行最终校验。因此解题关键就是把这两层变换完整逆向出来。

继续分析 \`CryptoEngine.transform()\`，发现其参数不是写死在代码里的，而是从 \`assets/telemetry.bin\` 中动态加载。该文件一共四行，分别对应 \`shifts\`、\`mask\`、自定义 base64 字母表和目标密文。Java 层的变换逻辑可以概括为：先对可打印字符做一个基于 \`shifts\` 的循环位移，再异或 \`mask\`，然后叠加上一个字节结果 \`prev\` 以及当前位置偏移 \`i * 3\`，最终生成新的字节数组。由于这个过程是逐字节、有状态的，因此逆向时需要按顺序逐位恢复。

随后进入 Native 层分析 \`NativeBridge.verify()\`，可以看到程序会先对 Java 层输出的字节数组做一轮 LFSR 混淆，初始种子是 \`0x5d\`，反馈位由 bit 0、2、3、5 共同决定。处理后的结果再与 \`telemetry.bin\` 中的目标字符串进行比较。不过目标字符串并不是标准 base64，而是使用自定义字母表编码，因此还需要先按自定义映射将其解码成原始字节序列。由于 Native 层本质上只是异或 LFSR 生成的流，所以逆向时同样可以直接利用异或对称性恢复出 Java 层应当产生的目标字节。

最后将自定义 base64 解码结果逆 LFSR 还原，再按 \`CryptoEngine.transform()\` 的逆过程逐字节恢复明文，即可得到花括号内部内容为 \`abyssal_vows_bind_the_last_protocol\`，最终拼接出完整 flag。

Exp：

```python

\#!/usr/bin/env python3

shifts = bytes.fromhex('0b04110916060d')

mask = bytes.fromhex('1337c0de42a5197f')

alphabet = 'Qh2s7Ca9VxN4fKpB8J1mL+zoF0ewAyOu3DrRYSgPItU6McdkXl/WTnGEZ5ivbHjq'

target_b64 = 'T8GHtJzYDRX7siXzWKLJCGlrpi1sVwnvMhZCPj3jwDWYU4Y='

char_to_idx = {c: i for i, c in enumerate(alphabet)}

decoded = []

bits = bit_count = 0

for c in target_b64:

if c == '=':

break

bits = (bits &lt;&lt; 6) | char_to_idx[c]

bit_count += 6

if bit_count &gt;= 8:

bit_count -= 8

decoded.append((bits &gt;&gt; bit_count) & 0xff)

state, counter = 0x5d, 0

xor_stream = []

for _ in range(len(decoded)):

taps = state \^ (state &gt;&gt; 2) \^ (state &gt;&gt; 3) \^ (state &gt;&gt; 5)

feedback = taps & 1

new_state = (state &gt;&gt; 1) | (feedback &lt;&lt; 7)

xor_stream.append((counter + new_state) & 0xff)

state, counter = new_state, counter + 7

expected = bytes(d \^ x for d, x in zip(decoded, xor_stream))

prev = 0

inner = []

for i, target in enumerate(expected):

x = (target - prev - i * 3) & 0xff

before_xor = x \^ mask[i % len(mask)]

shift = shifts[i % len(shifts)]

char_code = ((before_xor - 32 - shift) % 95) + 32

inner.append(chr(char_code))

prev = target

print(f"ISCC{{{''.join(inner)}}}")

```

Flag：

\`ISCC{abyssal_vows_bind_the_last_protocol}\`
