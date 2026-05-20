+++
title = "QuorumGlyph"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

逆向 + QuorumGlyph

解题思路（必须包含文字说明+截图）

1\. 基础信息

题目提示为 One witness lies. Two are incomplete. Three agree. 附件为 stripped 的 Linux x86_64 ELF，输入 flag 后输出 Yes??? / No???。

通过 strings 可以直接看到前缀 ISCC{QRM_ 和自定义字母表 ABCDEFGHJKLMNPQRSTUVWXYZ23456789。

2.  基础校验

    main 中先做长度和格式检查：输入长度必须为 42，前缀必须是 ISCC{QRM_，第 14 个字符必须为 _，最后一个字符必须为 }，并且所有字符都要落在 0x21..0x7e。

因此 flag 结构先确定为 ISCC{QRM_?????_??????????????????????????}。

2.  第一层 witness 校验

    程序把输入复制到栈上，再每 8 字节组成一个 qword，

随后进入 144 轮奇偶校验。这里有一个关键点：进入强变换前，程序会把第 9 到第 13 个字符清零，因此这 5 个未知字符不参与这一层。

这一层本质上是对剩余字符做多轮 parity 约束，对应题目提示里的 multiple witnesses。它只能缩小范围，不能单独给出完整 flag。

2.  第二层 64 字节强变换

    程序在构造函数里先生成一个 64 字节目标缓冲区，生成方式是常量表配合 splitmix64 风格混淆。随后对 16 个 dword 做 37 轮可逆变换，每轮包括：异或递增 key 后循环左移、正向滚动异或、反向滚动异或、按低 4 bit 交换 dword。

把这段目标缓冲区逆回去后，可以恢复出前 42 字节为 ISCC{QRM_....._3_w1tness_no_single_path!!}。其中 ..... 正好对应前面被清零的 5 个未知字符。

因此 flag 进一步缩小为 ISCC{QRM_?????_3_w1tness_no_single_path!!}。

5\. 第三层 5 字符单独校验

最后程序单独取这 5 个字符，要求它们全部来自字母表 ABCDEFGHJKLMNPQRSTUVWXYZ23456789。5 个字符被编码成一个 25 bit 值，并要求不超过 0xffffff。

编码后的值先经过一个 24 bit 变换，再传入 401ca0。401ca0 会生成 0x400 项的 qword 表，并做 0x600 轮扰动，最后返回一个 64 bit 哈希值，与常量 0xe04cf5339f776142 比较。

复现 401ca0 时最容易写错的地方在函数末尾：不是直接 rcx = table[rsi & 0x3ff]，而是 rcx = rcx_state \^ table[rsi & 0x3ff]。如果漏掉这个细节，全量爆破不会命中。

6\. 爆破与结果

将最后 5 个字符按自定义 Base32 编码后，枚举 0x000000 到 0xffffff 的所有候选，复现 transform 和 401ca0，命中值为 FE6V6。

最终 flag 为：ISCC{QRM_FE6V6_3_w1tness_no_single_path!!}

7\. 验证

将最终 flag 输入原程序，输出 Yes???，验证通过。

Exp（如有，请粘贴完整代码，不允许截图！）

\#include &lt;stdint.h&gt;

\#include &lt;stdio.h&gt;

\#include &lt;stdlib.h&gt;

\#include &lt;time.h&gt;

static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

static const uint64_t target = 0xe04cf5339f776142ULL;

static inline uint64_t rotl64(uint64_t x, unsigned r) {

r &= 63;

return r ? ((x &lt;&lt; r) | (x &gt;&gt; (64 - r))) : x;

}

static inline uint64_t mix64(uint64_t x) {

x \^= x &gt;&gt; 30;

x *= 0xbf58476d1ce4e5b9ULL;

x \^= x &gt;&gt; 27;

x *= 0x94d049bb133111ebULL;

x \^= x &gt;&gt; 31;

return x;

}

static uint64_t heavy(uint32_t in) {

uint64_t table[0x400];

uint64_t rsi = in;

uint64_t rdx = 0x9e3779b1ULL;

uint64_t rax = 0xb198fa1458a7836cULL \^ rsi;

rsi *= rdx;

rsi \^= 0xc5c9afd93ff67d70ULL;

uint64_t rdi = 0;

rdx = 0;

for (uint64_t i = 0; i &lt; 0x400; i++) {

uint64_t rcx = rdx + 0x9e3779b97f4a7c15ULL + rax;

rax = mix64(rcx);

rcx = rax \^ rdi;

rdi += 0x100000001b3ULL;

rsi \^= rcx;

rsi = mix64(rsi);

table[i] = rotl64(rsi, (unsigned)i) \^ rax;

rdx++;

}

uint64_t r10 = 0;

uint64_t r9 = 0;

rdi = 0;

uint64_t rcx_state = 0;

while (rdi != 0x600) {

rdx = rax;

uint64_t rcx = rax + r10;

uint64_t r13 = rdi &lt;&lt; 7;

rdx \^= rsi;

rdx \^= rdi;

uint64_t r8 = table[rdx & 0x3ff];

rdx = rax &gt;&gt; 17;

rcx += r8;

rdx \^= r9;

rax = mix64(rcx);

rdx \^= r8;

uint64_t t = table[rdx & 0x3ff];

rcx = rax;

uint64_t r12 = t + rax;

rcx &gt;&gt;= 59;

r12 = rotl64(r12, (unsigned)rcx);

rsi \^= r12;

r12 = r8 + rdi + t;

r8 \^= r13;

r8 \^= rsi;

rcx = rsi \^ rax;

uint32_t idx = (uint32_t)r8 & 0x3ff;

rdx = mix64(r12);

rdi++;

r9 += 0x83;

r10 += 0xd6e8feb86659fd93ULL;

rdx \^= rcx;

table[idx] = rdx;

rcx_state = rcx;

}

rsi += rax;

uint64_t rcx = rcx_state \^ table[rsi & 0x3ff];

rcx \^= 0x51474c5950484153ULL;

return mix64(rcx);

}

static inline uint32_t transform(uint32_t v) {

uint32_t eax = 1;

for (int i = 0; i &lt; 5; i++) {

uint32_t esi = eax * 0x00d1e995U;

uint32_t ecx = 2U - esi;

eax *= ecx;

}

return (eax * (v - 0x00b3ef33U)) & 0x00ffffffU;

}

static void print_candidate(uint32_t v) {

char s[6];

for (int i = 4; i &gt;= 0; i--) {

s[i] = alphabet[v & 31];

v &gt;&gt;= 5;

}

s[5] = 0;

puts(s);

}

int main(int argc, char **argv) {

uint32_t limit = 0x1000000U;

if (argc &gt; 1) {

limit = (uint32_t)strtoul(argv[1], NULL, 0);

}

clock_t start = clock();

for (uint32_t v = 0; v &lt; limit; v++) {

if (heavy(transform(v)) == target) {

print_candidate(v);

return 0;

}

}

double secs = (double)(clock() - start) / CLOCKS_PER_SEC;

fprintf(stderr, "searched %u in %.3f sec\\n", limit, secs);

return 1;

}

Flag：ISCC{QRM_FE6V6_3_w1tness_no_single_path!!}

