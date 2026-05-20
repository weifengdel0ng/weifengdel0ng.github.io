+++
title = "北极星混淆"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

\# ISCC2026 WriteUp


Reverse-北极星混淆

---

\#\# 解题思路

\#\#\# 1. 文件基础分析

拿到题目压缩包，解压得到一个 ELF 文件：

64-bit ELF，开 PIE，符号表已去除。用 \`pyelftools\` 解析内部结构：

| 段名 | 起始 VA | 大小 |

| ------ | ---------- | ---------- |

| .text | \`0x40e0\` | \`0x14954b\` |

| .rodata| \`0x14e000\` | \`0x33a64\` |

| .data | \`0x184000\` | \`0xc40\` |

| .bss | \`0x184c40\` | \`0x33770\` |

导入表很小，总共 12 个外部符号，说明大多数逻辑被静态嵌入或混淆在二进制内部：

\`\`\`

\_\_libc\_start\_main, \_\_cxa\_finalize, \_\_errno\_location

write, read, open, close, memset, memcpy

ptrace, getppid, clock\_gettime

\`\`\`

入口点 \`0x40e0\` 通过 \`\_\_libc\_start\_main\` 调用实际主逻辑，其第一个参数 RDI 即 main 地址：\*\*\`0x41d0\`\*\*。

---

\#\#\# 2. 反调试与执行环境搭建

导入表中 \`ptrace\`、\`getppid\`、\`clock\_gettime\` 这几个函数表明程序有反调试机制。跟踪发现它会：

- 调用 \`ptrace(PTRACE\_TRACEME, ...)\` 检测是否被调试；

- 打开并读取 \`/proc/self/status\`，检查 \`TracerPid\` 字段；

- 读 \`/proc/&lt;ppid&gt;/comm\` 检测父进程名；

- 用 \`clock\_gettime\` 做时间反调试。

如果直接在 WSL 中跑错误输入，输出 \`no\`，说明反调试某步触发了错误分支。解决方案是在 Unicorn 模拟器中为关键系统调用设置桩：

\`\`\`

ptrace → 返回 0

getppid → 返回 1234

open 读取 status → 返回虚拟 fd，内容中 TracerPid 置为 0

open 读取 comm → 返回虚拟 fd，内容为 "bash\\n"

clock\_gettime → 返回固定时间戳

\`\`\`

通过这些桩函数，程序在模拟环境中稳定地进入验证逻辑。

---

\#\#\# 3. 控制流混淆模式分析

二进制的主体充满了类似下面的混淆模式：

\`\`\`asm

call some\_gadget

; 这里返回到的地址并非 call 的下一条指令

; 因为 some\_gadget 内部修改了栈上的返回地址

\`\`\`

典型 gadget 位于 \`0x1b42c\`：

\`\`\`asm

0x1b42c: ... ; 一些指令

0x1b46b: add qword \[rax+0x58\], 0x29 ; 修改栈上的返回地址

0x1b481: ret ; 跳到跳过垃圾指令的位置

\`\`\`

这使得静态线性反汇编看到的指令流杂乱无章，但实际执行路径是连续有效的。因此本题不适合纯静态硬读，更有效的方式是用 Unicorn 动态跟踪，在关键点 Hook，记录真实执行轨迹。

---

\#\#\# 4. 定位关键辅助函数

尽管混淆严重，仍然能从 \`.text\` 中识别出几个结构规整的辅助函数：

| 地址 | 功能 |

| --------- | ----------------------------- |

| \`0x21870\` | 去除输入行尾 \`\\n \\r 空格 \\t\` |

| \`0xcf500\` | 文件读取（open→read→close） |

| \`0xcf5b0\` | 字符串子串匹配 |

| \`0xcf680\` | 获取时间（clock\_gettime） |

| \`0xcf6c0\` | 32 位循环左移 rol32 |

| \`0xcf710\` | 白盒表初始化 |

其中 \`0xcf6c0\` 的 \`rol32\` 实现非常典型：

\`\`\`asm

mov eax, esi

and eax, 0x1f

; ...

shl eax, cl

shr edx, cl

or eax, ecx

\`\`\`

---

\#\#\# 5. 白盒表解码

表初始化函数 \`0xcf710\` 调用 \`0x14cff0\` 五次，从 \`.rodata\` 中的加密数据生成五张工作表：

| 表 | 稀疏源表地址 | 解码后地址 | 大小 | 解码种子 |

| ---- | ------------ | ---------- | -------- | ------------------ |

| 目标 | \`0x183bc0\` | \`0x184c80\` | \`0x30\` | \`0x61f29c0d87a453b1\` |

| A | \`0x183bf0\` | \`0x184cc0\` | \`0xa000\` | \`0xd3b5407c19ea8f26\` |

| B | \`0x183c50\` | \`0x18ecc0\` | \`0x24000\`| \`0x7a8ce153d604b92f\` |

| C | \`0x183cc0\` | \`0x1b2cc0\` | \`0x1000\` | \`0xc94e2f81a73d650b\` |

| D | \`0x183d00\` | \`0x1b3cc0\` | \`0x4000\` | \`0x2f6dba904c18e357\` |

解码函数 \`0x14cff0\` 的核心流程：

1\. 将种子、表长度、flag 混合生成初始状态；

2\. 计算一个与表长度互素的遍历步长；

3\. 利用 \*\*SplitMix64\*\*（地址 \`0x14d250\`）生成伪随机序列；

4\. 从稀疏指针表取字节，与随机数 XOR，按置换顺序写入目标缓冲区。

SplitMix64 的魔数常量在反汇编中非常容易识别：

\`\`\`

0x9e3779b97f4a7c15 (golden ratio φ)

0xbf58476d1ce4e5b9

0x94d049bb133111eb

\`\`\`

第一张表（48 字节）解码结果即为最终的比较目标密文：

\`\`\`

c6bae55d0275ac4f4a5da18fda143fa9

486079b58b82039a59c160821547e384

25af09ae621b3fe309e45f929f64002c

\`\`\`

---

\#\#\# 6. 动态 Hook 定位比较点

Hook \`write\` 系统调用，观察到错误输出路径：

\`\`\`

write(1, "no\\n", 3)

\`\`\`

沿调用栈回溯，找到最终的差异累积点位于 \`0xc3d8d\`：

\`\`\`asm

0xc3d8d: mov \[rsi+0x57\], rcx ; 写入比较差异值

0xc3d95: lea rdi, \[rbp-0x890\]

0xc3d9c: ret

\`\`\`

这里每一轮会将 \`encrypt(in\[i\]) \^ target\[i\]\` 写入 \`RCX\`。在 Hook 中提取 \`RCX & 0xff\` 并清零，即可逐字节收集非累积差异。

对探针输入 \`ISCC{AAAA...AA}\`（40字节），得到 48 字节差异：

\`\`\`

72 b6 fa 81 0b f0 4a 44 b9 6e 4e 51 e3 5f b2 89

1c 05 ab db 1d bb b7 9a 67 49 f7 27 15 ef 53 64

0d 1b 4d 1f 65 b7 53 1e b3 6b 6d 1d 84 d3 a8 13

\`\`\`

---

\#\#\# 7. 分组模式与 Padding 确认

通过变动不同输入字节观察差异变化范围：

- 输入第 0～15 字节仅影响差异第 0～15 字节；

- 输入第 16～31 字节仅影响差异第 16～31 字节；

- 输入第 32～39 字节影响差异第 32～47 字节。

证明算法是 \*\*16 字节 ECB 分组模式\*\*。

输入 40 字节，输出 48 字节密文，符合 \*\*PKCS\#7 padding\*\*：\`40 + pad(8) → 48\`，padding 字节均为 \`0x08\`。

---

\#\#\# 8. 白盒网络结构还原

通过 Hook 各表的访问序列，绘制出一轮内的查表模式：

\`\`\`

A 表: 16 次单字节查表（输入编码/S-Box 编码）

B 表: 64 次单字节查表（T-Box / MixColumns 合并表）

\`\`\`

\*\*9 轮\*\*结构完全一致，最后一轮略有不同：

\`\`\`

轮 0～8: A → B(含 Mix) → 下一轮

轮 9: A → C(末轮输出编码) → 与目标比较

\`\`\`

对照 AES 标准 ShiftRows 排列，反推出列分组关系：

\`\`\`

group\[0\] = \[0, 5, 10, 15\]

group\[1\] = \[4, 9, 14, 3\]

group\[2\] = \[8, 13, 2, 7\]

group\[3\] = \[12, 1, 6, 11\]

\`\`\`

单轮加密逻辑还原为：

\`\`\`

for each round r (0..8):

for each byte i:

enc\[i\] = A\_table\[(r\*16 + i)\*256 + state\[i\]\]

for each column col:

for each row in 0..3:

out\_pos = col\*4 + row

next\[out\_pos\] = XOR over k in 0..3:

B\_table\[(r\*64 + out\_pos\*4 + k)\*256 + enc\[group\[col\]\[k\]\]\]

\`\`\`

末轮也需要应用 ShiftRows 排列才能得到正确的输出。

---

\#\#\# 9. Meet-in-the-Middle 解密策略

解密即求 \`encrypt(明文) = 目标密文\`，采用逐块逆推。

\*\*逆末轮\*\*：每字节输出为单表置换，直接建反表查回。

\*\*逆混合层\*\*：每列 4 字节输出由 4 个输入字节 XOR 得到：

\`\`\`

Y\[row\] = T0\[x0\] \^ T1\[x1\] \^ T2\[x2\] \^ T3\[x3\]

\`\`\`

暴力枚举 4 字节为 \`256\^4 = 2\^32\`，开销太大。采用 \*\*MITM\*\* 降复杂度：

1\. 枚举 \`(x0, x1)\`，算出对 4 字节输出的贡献，存入哈希表；

2\. 枚举 \`(x2, x3)\`，计算 \`Y \^ T2\[x2\] \^ T3\[x3\]\` 并在哈希表中查找；

3\. 命中即得完整 4 元组。

复杂度降为 \`256\^2 × 2 ≈ 1.3 × 10\^5\` 次查表，完全可行。每轮 4 列，逆推 9 轮即可还原一整块 16 字节明文。

---

\#\#\# 10. 解密得 Flag

对 48 字节目标密文分 3 块分别解密：

\`\`\`

块 0: c6bae55d0275ac4f 4a5da18fda143fa9

块 1: 486079b58b82039a 59c160821547e384

块 2: 25af09ae621b3fe3 09e45f929f64002c

\`\`\`

解密得到：

\`\`\`

49 53 43 43 7b 72 65 61 6c 5f 77 68 69 74 65 62 ISCC{real\_whiteb

6f 78 5f 41 45 53 5f 77 69 74 68 5f 70 6f 6c 61 ox\_AES\_with\_pola

72 69 73 5f 6d 69 72 7d 08 08 08 08 08 08 08 08 ris\_mir}........

\`\`\`

去掉尾部的 8 个 \`0x08\` padding 字节：

\`\`\`

ISCC{real\_whitebox\_AES\_with\_polaris\_mir}

\`\`\`

---

\#\#\# 11. 结果验证

在 Unicorn 中加载反调试桩函数，向程序输入解出的 flag：

\`\`\`

输入: ISCC{real\_whitebox\_AES\_with\_polaris\_mir}\\n

输出: ok

比对结果: iszero 参数 = 0

\`\`\`

验证通过。

---

\#\# Exp

\`\`\`python

from elftools.elf.elffile import ELFFile

import struct, math

ELF\_PATH = "re"

M64 = (1 &lt;&lt; 64) - 1

def rd\_u64(data):

return struct.unpack("&lt;Q", data)\[0\]

class BinImg:

def \_\_init\_\_(self, path):

self.\_raw = open(path, "rb").read()

with open(path, "rb") as fh:

elf = ELFFile(fh)

self.\_maps = \[

(s\["p\_vaddr"\], s\["p\_offset"\], s\["p\_filesz"\])

for s in elf.iter\_segments()

if s\["p\_type"\] == "PT\_LOAD"

\]

def \_off(self, va):

for vaddr, offset, fsize in self.\_maps:

if vaddr &lt;= va &lt; vaddr + fsize:

return offset + va - vaddr

raise LookupError(f"VA {va:\#x} 不在文件映射范围内")

def get(self, va, size):

o = self.\_off(va)

return self.\_raw\[o:o + size\]

def get64(self, va):

return rd\_u64(self.get(va, 8))

def sm64(state):

"""SplitMix64 单步迭代"""

s = (state + 0x9E3779B97F4A7C15) & M64

z = s

z = ((z \^ (z &gt;&gt; 30)) \* 0xBF58476D1CE4E5B9) & M64

z = ((z \^ (z &gt;&gt; 27)) \* 0x94D049BB133111EB) & M64

return s, (z \^ (z &gt;&gt; 31)) & M64

def rand\_seed(orig\_seed, length, flag=0):

"""种子混合"""

v = (orig\_seed

\^ ((length \* 0xD1342543DE82EF95) & M64)

\^ ((flag \* 0x6A09E667F3BCC909) & M64)) & M64

a = 0

for \_ in range(4):

v, r = sm64(v \^ a)

a = (a \^ r) & M64

return a

def find\_step(n, seed):

"""计算与 n 互素的遍历步长"""

s = ((seed &gt;&gt; 17) | 1) % n

if s == 0:

s = 1

while math.gcd(s, n) != 1:

s = (s + 2) % n

if s == 0:

s = 1

return s

def ptr\_pick(img, base, width, seed, idx):

"""从稀疏指针表中取一个字节"""

step = find\_step(width, seed)

off = (seed &gt;&gt; 23) % width

pi = (idx \* step + off) % width

ptr = img.get64(base + pi \* 8)

return img.get(ptr + idx // width, 1)\[0\]

def table\_decode(img, src, length, seed, width, flag=0):

"""解码一张白盒表"""

rng = rand\_seed(seed, length, flag)

step = find\_step(length, rng)

r2 = (rand\_seed(0xA5A5A5A55A5A5A5A \^ rng, length, 0) &gt;&gt; 19) % length

st = rng

buf = bytearray(length)

for i in range(length):

dst = (i \* step + r2) % length

st, rv = sm64(st)

b = (rv &gt;&gt; ((i & 7) \* 8)) & 0xFF

b \^= (dst \* 0xA7 + i \* 0x3D) & 0xFF

b \^= ptr\_pick(img, src, width, seed, i)

buf\[dst\] = b

return bytes(buf)

def load\_all\_tables(img):

"""加载全部五张白盒表"""

tgt = table\_decode(img, 0x183BC0, 0x30, 0x61F29C0D87A453B1, 5)

enc = table\_decode(img, 0x183BF0, 0xA000, 0xD3B5407C19EA8F26, 11)

mix = table\_decode(img, 0x183C50, 0x24000, 0x7A8CE153D604B92F, 13)

fout = table\_decode(img, 0x183CC0, 0x1000, 0xC94E2F81A73D650B, 7)

aux = table\_decode(img, 0x183D00, 0x4000, 0x2F6DBA904C18E357, 9)

return tgt, enc, mix, fout

\# ShiftRows 列分组

COLS = \[

(0, 5, 10, 15),

(4, 9, 14, 3),

(8, 13, 2, 7),

(12, 1, 6, 11),

\]

\# 末轮也需 ShiftRows

LAST\_PERM = \[p for g in COLS for p in g\]

def wb\_enc\_one(blk, enc\_t, mix\_t, fout\_t):

"""白盒AES加密单块（16字节 → 16字节）"""

s = list(blk)

for rnd in range(9):

e = \[enc\_t\[(rnd \* 16 + i) \* 256 + s\[i\]\] for i in range(16)\]

nxt = \[0\] \* 16

for ci, grp in enumerate(COLS):

for ri in range(4):

pos = ci \* 4 + ri

v = 0

for ki, sp in enumerate(grp):

tid = rnd \* 64 + pos \* 4 + ki

v \^= mix\_t\[tid \* 256 + e\[sp\]\]

nxt\[pos\] = v

s = nxt

e = \[enc\_t\[(9 \* 16 + i) \* 256 + s\[i\]\] for i in range(16)\]

return bytes(fout\_t\[j \* 256 + e\[LAST\_PERM\[j\]\]\] for j in range(16))

def make\_last\_inv(enc\_t, fout\_t):

"""构建末轮逆映射"""

invs = \[\]

for op, sp in enumerate(LAST\_PERM):

m = {}

for x in range(256):

y = fout\_t\[op \* 256 + enc\_t\[(9 \* 16 + sp) \* 256 + x\]\]

m\[y\] = x

if len(m) != 256:

raise RuntimeError(f"末轮位置 {op} 不是双射")

invs.append((sp, m))

return invs

def inv\_col(rnd, ci, target4, enc\_t, mix\_t, memo):

"""MITM 逆解一列（4 字节梯度）"""

k = (rnd, ci, target4)

if k in memo:

return memo\[k\]

grp = COLS\[ci\]

base = rnd \* 64 + ci \* 4

\# 预计算每行贡献

contrib = \[\[\], \[\], \[\], \[\]\]

for ki, sid in enumerate(grp):

for x in range(256):

val = enc\_t\[(rnd \* 16 + sid) \* 256 + x\]

contrib\[ki\].append(\[

mix\_t\[(base \* 4 + ri \* 4 + ki) \* 256 + val\]

for ri in range(4)

\])

\# LHS: x0 ⊕ x1

lhs = {}

for x0 in range(256):

for x1 in range(256):

lhs\[bytes(contrib\[0\]\[x0\]\[r\] \^ contrib\[1\]\[x1\]\[r\] for r in range(4))\] = (x0, x1)

\# RHS: 搜索 x2 ⊕ x3 = target4 ⊕ lhs

for x2 in range(256):

for x3 in range(256):

need = bytes(target4\[r\] \^ contrib\[2\]\[x2\]\[r\] \^ contrib\[3\]\[x3\]\[r\] for r in range(4))

if need in lhs:

ans = lhs\[need\] + (x2, x3)

memo\[k\] = ans

return ans

raise RuntimeError(f"轮 {rnd} 列 {ci} 无解")

def wb\_dec\_one(blk, enc\_t, mix\_t, fout\_t):

"""白盒AES解密单块"""

last\_inv = make\_last\_inv(enc\_t, fout\_t)

s = \[0\] \* 16

for op, b in enumerate(blk):

sp, m = last\_inv\[op\]

s\[sp\] = m\[b\]

memo = {}

for rnd in range(8, -1, -1):

prev = \[0\] \* 16

for ci, grp in enumerate(COLS):

y4 = bytes(s\[ci \* 4:ci \* 4 + 4\])

vals = inv\_col(rnd, ci, y4, enc\_t, mix\_t, memo)

for ki, sid in enumerate(grp):

prev\[sid\] = vals\[ki\]

s = prev

return bytes(s)

def strip\_pkcs7(data):

"""去除 PKCS\#7 padding"""

n = data\[-1\]

if not (1 &lt;= n &lt;= 16) or data\[-n:\] != bytes(\[n\]) \* n:

raise ValueError("padding 校验失败")

return data\[:-n\]

def main():

img = BinImg(ELF\_PATH)

tgt, enc, mix, fout = load\_all\_tables(img)

\# 分块解密

pt = b"".join(

wb\_dec\_one(tgt\[i:i + 16\], enc, mix, fout)

for i in range(0, len(tgt), 16)

)

flag = strip\_pkcs7(pt).decode()

\# 结果验证：用探针输入确认加密网络正确

probe = b"ISCC" + b"A" \* 35

pad = probe + b"\\x08" \* 8

ct = b"".join(

wb\_enc\_one(pad\[i:i + 16\], enc, mix, fout)

for i in range(0, len(pad), 16)

)

ref = bytes.fromhex(

"72b6fa810bf04a44b96e4e51e35fb289"

"1c05abdb1dbbb79a6749f72715ef5364"

"0d1b4d1f65b7531eb36b6d1d84d3a813"

)

assert bytes(a \^ b for a, b in zip(ct, tgt)) == ref, "加密网络验证失败"

print("验证通过 ✓")

print(flag)

if \_\_name\_\_ == "\_\_main\_\_":

main()

\`\`\`

---

\*\*最终 flag：\*\*

\`\`\`

ISCC{real\_whitebox\_AES\_with\_polaris\_mir}

\`\`\`
