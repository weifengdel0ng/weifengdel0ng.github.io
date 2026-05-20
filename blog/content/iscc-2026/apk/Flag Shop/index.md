+++
title = "Flag Shop"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Mobile 移动安全 - Flag Shop

\# 解题思路

\#\# 一、题目概述

拿到题目附件 \`FlagShop.apk\` 后，题面给出重要线索：所有 fakeflag 的明文均为 \`ISCC{fakeflagfake}\`。这说明 APK 内部存储了多个商品的加密数据，但明文是一致的，真正 flag 的明文与 fakeflag 不同，需要从 so 层的加密/校验逻辑入手还原。

核心解题路线：

1\. 反编译 APK 提取 DEX，梳理商品列表与 native 调用关系

2\. 逆向 \`libflagshop.so\`，恢复管理员登录凭据

3\. 编写 Unicorn 本地仿真脚本，用 fakeflag 样本打通 oracle

4\. 将 oracle 切换到 realflag，恢复真实 flag

---

\#\# 二、DEX 层信息提取

使用 jadx 反编译 APK，在 DEX 中找到商品初始化代码。程序定义了 4 个商品：

| 商品 ID | 说明 |

|---------|------|

| \`fakeflag1\` | 虚假 flag 商品 1 |

| \`fakeflag2\` | 虚假 flag 商品 2 |

| \`fakeflag3\` | 虚假 flag 商品 3 |

| \`realflag\` | 真实 flag 商品 |

每个商品关联的并不是明文 flag，而是一段十六进制密文 \`encryptedHex\`。这说明 flag 不是直接存储的，而是经过某种 native 加密处理后的结果。

提取到的四组密文数据如下。

fakeflag1 对应密文：

\`\`\`

46534850840912118da77c2d7f480b5a3497e1c9cfd5fb6a15ffc5a68067f7bbd6b07028b9d52e53f1ea68d460c840a407db326f5e986d7e1305f8df01796fc56e188068355aff017715c6673d15e5f3af30a9e818e229d8

\`\`\`

fakeflag2 对应密文：

\`\`\`

46534850840912112ba9a049c2cc27ba76c2fd1340624573a1133272a504c589b360fac0d187c7db0346ad02dc4e38638e5f336155f28b64d71ae1f61769c6c91c3130d83d675755ee56f0d5c4bd74a07e4c794222cef2f2

\`\`\`

fakeflag3 对应密文：

\`\`\`

465348508409121105764efa14c617d84804c0e4f4e669ea8f5abd029b6b5c7a0ded5b1cdd0abb7f1cd9b765fe9e9009bd0e8e3f4354746c5e20f6d946ff2ff2fadcefcab00bb06984633a4ca24a690368951c43d8a507c5

\`\`\`

realflag 对应密文：

\`\`\`

4653485084083011788fb5d735cfa35810b48a3433ced888c02965457ad21cf80e4936cc8a536fee26b3ffc2a64981a878511f0d3ab96cdd05879fac83f005f9b5e311fa07d299b0d0580b4611afd6c8a4db205c1f278134

\`\`\`

继续在 DEX 中追踪调用链，定位到 native 方法声明：

\`\`\`

NativeBridge.encryptFlag(String, String, String, String): String

\`\`\`

通过向上追溯调用点，确定四个参数的语义分别为：

\`\`\`java

encryptFlag(itemId, flagInput, username, password)

\`\`\`

这个参数顺序在后续 Unicorn 仿真中至关重要，传错顺序会导致整个 oracle 走失败路径。

---

\#\# 三、SO 层逆向分析

核心逻辑位于 \`libflagshop.so\`（arm64-v8a 架构）。使用 IDA Pro 加载后，定位到以下关键函数：

| 函数 | 功能 |

|------|------|

| \`adminLogin\` | 管理员账号密码校验 |

| \`encryptFlag\` | 商品 flag 的加密/校验入口 |

| \`helper\_copy\_jstring\` | JNI 字符串转 std::string |

| \`helper\_compare\_or\_transform\` | 字符串比较 / 变换辅助函数 |

可以得出结论：

- 管理员身份认证完全在 so 层完成，DEX 层无任何明文凭据

- flag 的加密与校验逻辑同样在 so 层，无法直接从 DEX 恢复

- 必须通过 native 仿真获取真实 flag

---

\#\# 四、管理员凭据还原

\#\#\# 4.1 用户名

在 \`.rodata\` 段搜索与管理员相关的字符串，结合 \`adminLogin\` 函数中字符串比较指令的交叉引用，确认用户名为：

\`\`\`

admin

\`\`\`

\#\#\# 4.2 密码恢复

密码的恢复过程相对复杂。密码不是在 rodata 中直接明文存储的，而是在 so 初始化阶段由密码生成函数运行时写入 \`.bss\` 段。

对密码初始化逻辑进行局部仿真，在地址 \`0xf6f67\` 附近追踪 \`.bss\` 段的写入操作。经过单步跟踪，最终在内存中恢复出完整密码：

\`\`\`

FlagShopAdmin2026

\`\`\`

这里有一个非常容易踩的坑：密码末尾的 \`6\` 容易在逆向时被忽略。早期分析时容易误判为 \`FlagShopAdmin202\`，但少一个字符会导致 \`encryptFlag\` 内部校验失败，直接返回空字符串，不会进入真正的加密流程。

验证方式：分别用 \`FlagShopAdmin202\` 和 \`FlagShopAdmin2026\` 走 \`encryptFlag\`——

- 前者：函数命中失败分支，没有任何有效输出

- 后者：函数进入真实处理路径

---

\#\# 五、Unicorn 本地仿真 Oracle 设计

为了让 \`encryptFlag\` 在脱离 Android 环境的情况下复现运行，采用 Unicorn Engine 对 \`libflagshop.so\` 进行 arm64 指令级仿真。

\#\#\# 5.1 内存布局

1\. \*\*映射 PT\_LOAD 段\*\*：遍历 ELF 的 LOAD 段，按虚拟地址映射到 Unicorn 内存空间，写入段数据并设置对应的 r/w/x 权限

2\. \*\*处理重定位表\*\*：遍历 \`.rela.dyn\` 和 \`.rela.plt\`，对类型为 \`R\_AARCH64\_RELATIVE\`（1027）的重定位项写入 \`base + addend\` 的值

3\. \*\*分配栈空间\*\*：在 \`0x2000000\` 分配栈内存，设置 SP 和 FP 寄存器

4\. \*\*构造 JNIEnv\*\*：在 \`0x3000000\` 区域构造一个假的 JNIEnv 和虚函数表 vtable

\#\#\# 5.2 函数桩 (Stub)

对于 so 依赖的外部函数，在 \`0x3100000\` 区域为每个导入符号分配一个桩地址，桩内容为 \`ret\` 指令。在每个桩被调用时，通过 hook 拦截并根据函数语义进行模拟：

| 函数 | 处理方式 |

|------|----------|

| \`strlen\` / \`strcmp\` / \`strncmp\` | 读取地址处 C 字符串，执行对应操作 |

| \`memcmp\` / \`memcpy\` / \`memmove\` / \`memset\` | 读取/写入原始内存字节 |

| \`malloc\` / \`realloc\` / \`free\` | 在仿真堆上分配/释放内存 |

| \`\_\_system\_property\_get\` | 模拟 Android 系统属性读取（反 frida 检测返回 "1"） |

| \`getpid\` | 返回固定值 1234 |

| \`syscall\` | 返回 0 |

| \`abort\` / \`\_\_stack\_chk\_fail\` | 抛出异常终止仿真 |

\#\#\# 5.3 JNI 桥接

在 vtable 中 \`+0x538\` 偏移处（对应 \`NewStringUTF\`）替换为一个自定义桩地址。当 so 调用 \`NewStringUTF\` 返回 Java string 时，hook 拦截并记录返回的字符串内容，同时将 PC 直接返回调用者。

在地址 \`0x5007c\` 处（对应 \`helper\_copy\_jstring\` 的核心逻辑），检测到对 Java 字符串的拷贝操作，将 Java 字符串按 \`std::string\` 的 SSO（Small String Optimization）布局写入目标地址，绕过对 JNI 实际对象的依赖。

---

\#\# 六、Fakeflag 基准验证

题目已明确告知 fakeflag 明文为：

\`\`\`

ISCC{fakeflagfake}

\`\`\`

使用以下参数调用 \`encryptFlag\` 入口（地址 \`0x517a8\`）：

| 参数 | 值 |

|------|-----|

| itemId (X2) | \`fakeflag1\` |

| flagInput (X3) | \`ISCC{fakeflagfake}\` |

| username (X4) | \`admin\` |

| password (X5) | \`FlagShopAdmin2026\` |

\#\#\# 验证结果

- \*\*错误密码\*\*（少一个 \`6\`）：仿真结束，\`encryptFlag\` 走失败路径，返回值为空

- \*\*正确密码\*\*（\`FlagShopAdmin2026\`）：so 进入完整的处理路径，函数正常返回，且 \`NewStringUTF\` 被正确调用

这证实了：

1\. 管理员凭据完全正确

2\. 参数顺序 \`(itemId, flagInput, username, password)\` 完全正确

3\. JNI 桥接和函数桩工作正常

4\. 本地 oracle 状态可靠，可以迁移到 realflag

---

\#\# 七、Realflag 恢复

在 oracle 验证通过后，将仿真参数中的 itemId 切换为 \`realflag\`，flagInput 保持为真实 flag 的待求值。核心思路是：

1\. 将 \`encryptFlag\` 参数设为 \`("realflag", X, "admin", "FlagShopAdmin2026")\`

2\. 程序内部会用 \`X\` 与 so 中的真实 flag 进行比较

3\. 通过 hook \`strcmp\` / \`strncmp\` 桩函数，在每次比较时 dump 两个比较对象

4\. 从比较日志中提取 so 内部使用的真实 flag 明文

在 trace 日志中，\`strcmp\` 被调用时可以看到如下比较操作：

\`\`\`

('call', 'strcmp', ..., 'ISCC{7H15\_1\$\_r431\_f146\_4nd\_17\_h45n\\'7\_501d\_0u7?!}', 'ISCC{...}')

\`\`\`

由此恢复出真实 flag：

\`\`\`

ISCC{7H15\_1\$\_r431\_f146\_4nd\_17\_h45n'7\_501d\_0u7?!}

\`\`\`

---

---

\# Exp

\`\`\`python

import glob

import struct

from elftools.elf.elffile import ELFFile

from unicorn import Uc, UcError, UC\_ARCH\_ARM64, UC\_MODE\_ARM, UC\_PROT\_READ, UC\_PROT\_WRITE, UC\_PROT\_EXEC, UC\_PROT\_ALL, UC\_HOOK\_CODE

from unicorn.arm64\_const import \*

path = glob.glob(r'libflagshop.so')\[0\]

PAGE = 0x1000

def align\_down(x):

return x & \~(PAGE - 1)

def align\_up(x):

return (x + PAGE - 1) & \~(PAGE - 1)

def read\_cstr(mu, addr, limit=0x1000):

out = bytearray()

for i in range(limit):

b = mu.mem\_read(addr + i, 1)\[0\]

if b == 0:

break

out.append(b)

return out.decode('utf-8', 'replace')

def write\_cstr(mu, addr, s):

mu.mem\_write(addr, s.encode() + b'\\x00')

with open(path, 'rb') as f:

elf = ELFFile(f)

mu = Uc(UC\_ARCH\_ARM64, UC\_MODE\_ARM)

for seg in elf.iter\_segments():

if seg\['p\_type'\] != 'PT\_LOAD':

continue

vaddr = seg\['p\_vaddr'\]

memsz = seg\['p\_memsz'\]

filesz = seg\['p\_filesz'\]

start = align\_down(vaddr)

end = align\_up(vaddr + memsz)

perms = 0

flags = seg\['p\_flags'\]

if flags & 4:

perms |= UC\_PROT\_READ

if flags & 2:

perms |= UC\_PROT\_WRITE

if flags & 1:

perms |= UC\_PROT\_EXEC

mu.mem\_map(start, end - start, perms)

mu.mem\_write(vaddr, seg.data())

if memsz &gt; filesz:

mu.mem\_write(vaddr + filesz, b'\\x00' \* (memsz - filesz))

for secname in ('.rela.dyn', '.rela.plt'):

sec = elf.get\_section\_by\_name(secname)

if not sec:

continue

symtab = elf.get\_section(sec\['sh\_link'\]) if sec\['sh\_link'\] else None

for rel in sec.iter\_relocations():

rtype = rel\['r\_info\_type'\]

off = rel\['r\_offset'\]

addend = rel\['r\_addend'\] if rel.is\_RELA() else 0

if rtype == 1027:

mu.mem\_write(off, struct.pack('&lt;q', addend))

stack = 0x2000000

mu.mem\_map(stack, 0x200000, UC\_PROT\_ALL)

sp = stack + 0x1f0000

mu.reg\_write(UC\_ARM64\_REG\_SP, sp)

mu.reg\_write(UC\_ARM64\_REG\_X29, sp)

env = 0x3000000

vtbl = 0x3001000

mu.mem\_map(0x3000000, 0x30000, UC\_PROT\_ALL)

mu.mem\_write(env, struct.pack('&lt;Q', vtbl))

stub\_base = 0x3100000

mu.mem\_map(stub\_base, 0x10000, UC\_PROT\_ALL)

ret\_stub = b'\\xc0\\x03\\x5f\\xd6'

stub\_for = {}

stub\_i = 0

plt = elf.get\_section\_by\_name('.rela.plt')

if plt:

symtab = elf.get\_section(plt\['sh\_link'\])

for rel in plt.iter\_relocations():

sym = symtab.get\_symbol(rel\['r\_info\_sym'\]).name if rel\['r\_info\_sym'\] else ''

if sym not in stub\_for:

stub\_for\[sym\] = stub\_base + stub\_i \* 0x100

mu.mem\_write(stub\_for\[sym\], ret\_stub)

stub\_i += 1

mu.mem\_write(rel\['r\_offset'\], struct.pack('&lt;Q', stub\_for\[sym\]))

newstring\_stub = 0x3200000

mu.mem\_map(newstring\_stub, 0x1000, UC\_PROT\_ALL)

mu.mem\_write(newstring\_stub, ret\_stub)

mu.mem\_write(vtbl + 0x538, struct.pack('&lt;Q', newstring\_stub))

data = 0x3300000

mu.mem\_map(data, 0x40000, UC\_PROT\_ALL)

def cstr(addr, s):

write\_cstr(mu, addr, s)

return addr

item = cstr(data + 0x000, 'realflag')

flag = cstr(data + 0x100, 'ISCC{fakeflagfake}')

user = cstr(data + 0x200, 'admin')

pw = cstr(data + 0x300, 'FlagShopAdmin2026')

heap = 0x3400000

mu.mem\_map(heap, 0x40000, UC\_PROT\_ALL)

heap\_next = \[heap\]

def alloc(size, align=0x10):

cur = (heap\_next\[0\] + align - 1) & \~(align - 1)

heap\_next\[0\] = cur + size

return cur

def write\_std\_string(addr, s):

b = s.encode()

mu.mem\_write(addr, b'\\x00' \* 0x20)

if len(b) &lt;= 22:

mu.mem\_write(addr, bytes(\[len(b) &lt;&lt; 1\]) + b + b'\\x00' \* (23 - len(b)))

return

ptr = alloc(len(b) + 1)

mu.mem\_write(ptr, b + b'\\x00')

mu.mem\_write(addr, struct.pack('&lt;Q', 1))

mu.mem\_write(addr + 8, struct.pack('&lt;Q', len(b)))

mu.mem\_write(addr + 16, struct.pack('&lt;Q', ptr))

ret\_strings = \[\]

trace = \[\]

def decode\_std\_string(addr):

b0 = mu.mem\_read(addr, 1)\[0\]

if (b0 & 1) == 0:

n = b0 &gt;&gt; 1

raw = bytes(mu.mem\_read(addr + 1, n))

return raw.decode('utf-8', 'replace')

n = struct.unpack('&lt;Q', bytes(mu.mem\_read(addr + 8, 8)))\[0\]

p = struct.unpack('&lt;Q', bytes(mu.mem\_read(addr + 16, 8)))\[0\]

raw = bytes(mu.mem\_read(p, min(n, 0x200)))

return raw.decode('utf-8', 'replace')

def emulate\_symbol(sym):

x0 = mu.reg\_read(UC\_ARM64\_REG\_X0)

x1 = mu.reg\_read(UC\_ARM64\_REG\_X1)

x2 = mu.reg\_read(UC\_ARM64\_REG\_X2)

lr = mu.reg\_read(UC\_ARM64\_REG\_LR)

if sym == 'strlen':

trace.append(('call', sym, hex(lr), hex(x0), read\_cstr(mu, x0)\[:120\]))

mu.reg\_write(UC\_ARM64\_REG\_X0, len(read\_cstr(mu, x0).encode()))

elif sym == 'strcmp':

a = read\_cstr(mu, x0)

b = read\_cstr(mu, x1)

trace.append(('call', sym, hex(lr), a\[:80\], b\[:80\]))

mu.reg\_write(UC\_ARM64\_REG\_X0, (a &gt; b) - (a &lt; b))

elif sym == 'strncmp':

a = read\_cstr(mu, x0)\[:x2\]

b = read\_cstr(mu, x1)\[:x2\]

trace.append(('call', sym, hex(lr), a\[:80\], b\[:80\], x2))

mu.reg\_write(UC\_ARM64\_REG\_X0, (a &gt; b) - (a &lt; b))

elif sym == 'memcmp':

a = bytes(mu.mem\_read(x0, x2))

b = bytes(mu.mem\_read(x1, x2))

trace.append(('call', sym, hex(lr), x2, a\[:64\].hex(), b\[:64\].hex()))

mu.reg\_write(UC\_ARM64\_REG\_X0, (a &gt; b) - (a &lt; b))

elif sym in ('memcpy', '\_\_memcpy\_chk', 'memmove'):

trace.append(('call', sym, hex(lr), hex(x0), hex(x1), x2))

mu.mem\_write(x0, bytes(mu.mem\_read(x1, x2)))

mu.reg\_write(UC\_ARM64\_REG\_X0, x0)

elif sym == 'memset':

mu.mem\_write(x0, bytes(\[x1 & 0xff\]) \* x2)

mu.reg\_write(UC\_ARM64\_REG\_X0, x0)

elif sym == 'malloc':

mu.reg\_write(UC\_ARM64\_REG\_X0, alloc(max(x0, 1)))

elif sym == 'realloc':

p = alloc(max(x1, 1))

if x0:

mu.mem\_write(p, bytes(mu.mem\_read(x0, x1)))

mu.reg\_write(UC\_ARM64\_REG\_X0, p)

elif sym == 'free':

mu.reg\_write(UC\_ARM64\_REG\_X0, 0)

elif sym == '\_\_system\_property\_get':

prop = read\_cstr(mu, x0)

val = '1' if 'frida' in prop.lower() else ''

write\_cstr(mu, x1, val)

mu.reg\_write(UC\_ARM64\_REG\_X0, len(val))

elif sym == 'strstr':

hay = read\_cstr(mu, x0)

nee = read\_cstr(mu, x1)

idx = hay.find(nee)

mu.reg\_write(UC\_ARM64\_REG\_X0, 0 if idx &lt; 0 else x0 + idx)

elif sym == 'getpid':

mu.reg\_write(UC\_ARM64\_REG\_X0, 1234)

elif sym == 'syscall':

mu.reg\_write(UC\_ARM64\_REG\_X0, 0)

elif sym in ('abort', '\_\_stack\_chk\_fail'):

raise RuntimeError(sym)

else:

mu.reg\_write(UC\_ARM64\_REG\_X0, 0)

def hook\_code(mu, addr, size, user\_data):

if addr == 0x5007c:

src = mu.reg\_read(UC\_ARM64\_REG\_X1)

target = mu.reg\_read(UC\_ARM64\_REG\_X8)

s = read\_cstr(mu, src)

write\_std\_string(target, s)

trace.append(('copy', hex(target), s, bytes(mu.mem\_read(target, 24)).hex()))

mu.reg\_write(UC\_ARM64\_REG\_PC, mu.reg\_read(UC\_ARM64\_REG\_LR))

return

if addr == newstring\_stub:

s = read\_cstr(mu, mu.reg\_read(UC\_ARM64\_REG\_X1))

ret\_strings.append(s)

trace.append(('retstr', hex(mu.reg\_read(UC\_ARM64\_REG\_LR)), s\[:120\]))

mu.reg\_write(UC\_ARM64\_REG\_X0, mu.reg\_read(UC\_ARM64\_REG\_X1))

mu.reg\_write(UC\_ARM64\_REG\_PC, mu.reg\_read(UC\_ARM64\_REG\_LR))

return

if addr in (0x52280, 0x522b4, 0x522c8, 0x522f4, 0x52384, 0x523b8, 0x523cc, 0x523f8, 0x52464, 0x52498, 0x524ac, 0x524d8, 0x53024, 0x53058, 0x5306c, 0x53098, 0x53154, 0x53188, 0x5319c, 0x531c8, 0x5377c, 0x537a8, 0x537bc):

base = mu.reg\_read(UC\_ARM64\_REG\_X8)

target = struct.unpack('&lt;Q', bytes(mu.mem\_read(base, 8)))\[0\] if base else 0

trace.append(('indirect', hex(addr), hex(base), hex(target)))

for sym, stub in stub\_for.items():

if addr == stub:

trace.append(('ext', sym))

emulate\_symbol(sym)

mu.reg\_write(UC\_ARM64\_REG\_PC, mu.reg\_read(UC\_ARM64\_REG\_LR))

return

if addr == 0x6e1ac:

trace.append(('skip', hex(addr)))

mu.reg\_write(UC\_ARM64\_REG\_PC, mu.reg\_read(UC\_ARM64\_REG\_LR))

return

mu.hook\_add(UC\_HOOK\_CODE, hook\_code)

mu.reg\_write(UC\_ARM64\_REG\_X0, env)

mu.reg\_write(UC\_ARM64\_REG\_X1, 0x1234)

mu.reg\_write(UC\_ARM64\_REG\_X2, item)

mu.reg\_write(UC\_ARM64\_REG\_X3, flag)

mu.reg\_write(UC\_ARM64\_REG\_X4, user)

mu.reg\_write(UC\_ARM64\_REG\_X5, pw)

try:

mu.emu\_start(0x517a8, 0x56000, count=10000000)

print('EMU\_OK')

except Exception as e:

print('EMUERR', type(e).\_\_name\_\_, e)

print('PC', hex(mu.reg\_read(UC\_ARM64\_REG\_PC)))

print('LR', hex(mu.reg\_read(UC\_ARM64\_REG\_LR)))

print('RETCOUNT', len(ret\_strings))

for i, s in enumerate(ret\_strings\[:20\]):

print('RET', i, repr(s\[:200\]))

print('TRACECOUNT', len(trace))

for t in trace:

print('TRACE', t)

\`\`\`

---

\# 最终 Flag

\`\`\`

ISCC{7H15\_1\$\_r431\_f146\_4nd\_17\_h45n'7\_501d\_0u7?!}

\`\`\`
