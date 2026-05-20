+++
title = "Conway's trap"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

ISCC2026 WriteUp


Reverse——Conway's trap

解题思路

1\. 程序整体观察

运行附件中的 PE 程序后，终端先提示 "Enter seed:"，

等待输入 32 位 hex 字符串；通过后显示 "Correct Seed."，

接着提示 "Enter flag:"。

输入格式 \`ISCC{...}\` 后若花括号匹配则给出 "Correct format! But wrong content."。注意到这里有两类不同反馈——格式正确但内容错误——暗示 flag 校验阶段存在不止一条代码路径。

使用 IDA 定位到这些字符串的交叉引用，找到 main 函数的核心逻辑。main 大致分为两段：前半段处理 seed，后半段处理 flag。

2\. Seed 校验逆推

seed 输入为 32 个 hex 字符，程序通过 \`sscanf\` 格式化为 16 字节，然后调 \`sub\_401990\` 迭代 5 轮，最终结果转 hex 后与全局常量比对：

\`\`\`text

df7b6a5d4da0f5facf32c4ee4b28b792

\`\`\`

深入 \`sub\_401990\` 发现每轮操作分两层：

- 把 16 字节两两分组（共 8 组），对每组的 (a, b) 做 a' = (a + b) & 0xff, b' = ROL(b \^ a', 1)

- 一轮结束后整体左循环移位一个字节

由于加法模 256 和 ROL 均可逆，直接从目标常量反推即可。逆轮函数步骤为：先右循环移位恢复位置，对每组用 ROR 和减法反推原始值，如此迭代 5 次得到真正的 seed：

\`\`\`text

0b5e321c68e0e4fb2d972226e8c70f8d

\`\`\`

为了验证正确性，将得到的 seed 再正向跑 5 轮，结果与目标常量完全一致。

3\. Flag 校验阶段分析

flag 输入经过格式验证（以 \`ISCC{\` 开头、\`}\` 结尾）后，调用 \`sub\_401C10\` 提取花括号中间的正文，再将其传入 \`sub\_401EB0\`。

初看 \`sub\_401EB0\`，容易直接关注到函数末尾那条长 hex 比较——它把正文编码后与一个 53 字节的目标串比对：

\`\`\`text

5986898a77726599708c726f716a72757596868f82657b8a8b8a6f6e6f7a8b727998789075697a92758d7669837570876d8e789582

\`\`\`

但仔细回溯 main 的初始化代码，发现在进入 flag 校验前，程序通过 \`sub\_401E00\` 注册了一个异常处理器（SEH），同时把地址 \`sub\_401CB0\` 的首字节修改为 \`0xCC\`（即 int3 断点指令）。这样一来，每当 \`sub\_401CB0\` 被调用时，就会触发断点异常，执行流被 SEH handler 劫持转向 \`sub\_401D00\`。

而 \`sub\_401EB0\` 在逐字节编码正文的循环中，恰好每轮都调用 \`sub\_401CB0\`。这意味着实际参与处理的并非表面上的长 hex 比较逻辑，而是 \`sub\_401D00\` 中的隐藏校验。

4\. 提取隐藏校验常量与逆推 flag

\`sub\_401D00\` 内部仅在首次被调用时执行完整校验。它先通过一系列 mov 指令在栈上构造一段密文，再与 \`0xCC\` 异或得到 23 字节的真实目标值。校验公式可抽象为：

\`\`\`

for i in 0..22:

t = seed\[i & 0xF\] \^ body\[i\]

t = (t + i \* 0x17) & 0xFF

t = ROL(t, 3) \^ 0xAA

if t != secret\[i\]: fail

seed\[0:2\] = \[0xDE, 0xAD\]

\`\`\`

关键信号：校验通过后 seed 前两字节被置为 \`0xDE 0xAD\`，而 \`sub\_401EB0\` 返回前会检查这两个字节——如果是 \`0xDE 0xAD\` 则提前返回成功，完全跳过末尾的长 hex 串比对。这解释了为何“格式正确但内容错误”和长 hex 串都存在却并非真正的判据。

从二进制中定位到栈上 mov 指令的立即数，异或 \`0xCC\` 后得到隐藏目标：

\`\`\`text

80e8512fb19a9b1332a47888df95efc2ddbf8dab146f76

\`\`\`

逆推公式为：

\`\`\`

body\[i\] = seed\[i & 0xF\] \^ ((ROR(target\[i\] \^ 0xAA, 3) - i \* 0x17) & 0xFF)

\`\`\`

代入 seed 和 target 计算出 23 字节正文：

\`\`\`text

NocwosxmveVar{i9uEtwc5E

\`\`\`

最终 flag：

\`\`\`text

ISCC{NocwosxmveVar{i9uEtwc5E}

\`\`\`

5\. Exp

\`\`\`python

import re

from pathlib import Path

TARGET\_SEED = 'df7b6a5d4da0f5facf32c4ee4b28b792'

def \_rol8(v: int, n: int) -&gt; int:

return ((v &lt;&lt; n) | (v &gt;&gt; (8 - n))) & 0xFF

def \_ror8(v: int, n: int) -&gt; int:

return ((v &gt;&gt; n) | (v &lt;&lt; (8 - n))) & 0xFF

def undo\_one\_round(data: bytes) -&gt; bytes:

shifted = bytes(\[data\[-1\]\]) + data\[:-1\]

res = bytearray(16)

for i in range(0, 16, 2):

nl, nr = shifted\[i\], shifted\[i + 1\]

orig\_r = \_ror8(nr, 1) \^ nl

orig\_l = (nl - orig\_r) & 0xFF

res\[i\], res\[i + 1\] = orig\_l, orig\_r

return bytes(res)

def do\_one\_round(data: bytes) -&gt; bytes:

buf = bytearray(data)

for i in range(0, 16, 2):

a, b = buf\[i\], buf\[i + 1\]

na = (a + b) & 0xFF

nb = \_rol8(na \^ b, 1)

buf\[i\], buf\[i + 1\] = na, nb

return bytes(buf\[1:\]) + bytes(\[buf\[0\]\])

def recover\_seed() -&gt; bytes:

state = bytes.fromhex(TARGET\_SEED)

for \_ in range(5):

state = undo\_one\_round(state)

\# sanity check

assert state == bytes.fromhex('0b5e321c68e0e4fb2d972226e8c70f8d')

ck = state

for \_ in range(5):

ck = do\_one\_round(ck)

assert ck.hex() == TARGET\_SEED

return state

def fetch\_hidden\_constants(binary: bytes) -&gt; bytes:

pat = (

rb'\\xc7\\x45\\xe4(.{4})\\xc7\\x45\\xe8(.{4})\\xc7\\x45\\xec(.{4})'

rb'\\xc7\\x45\\xf0(.{4})\\xc7\\x45\\xf4(.{4})\\x66\\xc7\\x45\\xf8(.{2})\\xc6\\x45\\xfa(.)'

)

m = re.search(pat, binary, re.DOTALL)

if m is None:

raise SystemExit('hidden constants not located in binary')

raw = b''.join(m.groups())

return bytes(b \^ 0xCC for b in raw)

def decode\_body(seed: bytes, secret: bytes) -&gt; str:

chars = \[\]

for idx, ct in enumerate(secret):

v = \_ror8(ct \^ 0xAA, 3)

v = (v - (idx \* 0x17)) & 0xFF

pt = v \^ seed\[idx & 0xF\]

chars.append(pt)

body = bytes(chars).decode('latin-1')

\# sanity check

check = bytearray()

for i, ch in enumerate(body.encode('latin-1')):

t = seed\[i & 0xF\] \^ ch

t = (t + (i \* 0x17)) & 0xFF

t = \_rol8(t, 3) \^ 0xAA

check.append(t)

assert bytes(check) == secret

return body

def main():

exe = Path(\_\_file\_\_).resolve().parent / "Conway's Trap.exe"

if not exe.is\_file():

alt = next(Path(\_\_file\_\_).resolve().parent.parent.glob('Reverse2-\*'), None)

if alt:

exe = alt / "Conway's Trap.exe"

raw = exe.read\_bytes()

seed = recover\_seed()

print(f'\[+\] seed : {seed.hex()}')

hidden = fetch\_hidden\_constants(raw)

print(f'\[+\] secret: {hidden.hex()}')

body = decode\_body(seed, hidden)

print(f'\[+\] body : {body}')

print(f'\[\*\] flag : ISCC{{{body}}}')

if \_\_name\_\_ == '\_\_main\_\_':

main()

\`\`\`

运行结果输出：

\`\`\`

\[+\] seed : 0b5e321c68e0e4fb2d972226e8c70f8d

\[+\] secret: 80e8512fb19a9b1332a47888df95efc2ddbf8dab146f76

\[+\] body : NocwosxmveVar{i9uEtwc5E

\[\*\] flag : ISCC{NocwosxmveVar{i9uEtwc5E}

\`\`\`
