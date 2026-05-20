+++
title = "喧宾夺主的信号"
date = "2026-05-15"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


MISC + 喧宾夺主的信号

解题思路
--------

### 1. 分析流量包

使用 Python 解析 pcap 文件，发现流量包中有两种类型的流量：

-   **1500 个 UDP 数据包**：源 IP 192.168.1.100 → 组播地址 239.255.255.250:1900（SSDP）

-   **9 个 TCP 数据包**：192.168.1.100 ↔ 45.78.1.1:80

每个 UDP 包携带 28 字节的 base64 编码数据，共 1500 个包（其中 4 个是标记包）。

### 2. 标记包中的线索

在 UDP 数据包中，第 200、500、800、1100 号数据包（共 4 个）包含相同的 base64 字符串：

U2hlbmdEb25nSmlYaUAzNi0xLTY=

\
解码后为：

ShengDongJiXi@36-1-6

即成语 **"声东击西"**（三十六计第6计），暗示这些 UDP 数据包只是**佯攻**，真正重要的数据在其他地方。

3.  ### 真正的命令——TCP 数据包

    TCP 数据包 \#505 中携带了一个 HTTP POST 请求：

POST /command HTTP/1.1

Host: 45.78.1.1

Content-Type: application/json

Content-Length: 700

{"instruction": "UEsDBBQAAQA...AAAAAA==", "note": "This is the real command."}

instruction 字段是一个 base64 编码的 ZIP 文件。

### 4. 解密 ZIP

将 base64 解码后得到一个加密的 ZIP 文件，其中包含 image.png。

使用之前发现的密码 ShengDongJiXi@36-1-6 成功解密 ZIP（注意：Python zipfile 模块对 AES-256 加密的 ZIP 支持有限，需使用 7-Zip 等工具）：

7z x encrypted.zip -p"ShengDongJiXi@36-1-6"

提取出一张 100×100 像素的 RGB PNG 图片。

### 5. PNG 图片隐写分析

检查 PNG 数据，发现图片的 IDAT 块解压后共 30100 字节（每行 301 字节 = 1 字节 filter + 300 字节 RGB 数据）。

关键发现：**PNG 使用了行过滤算法**（Filter Type 1/Sub、2/Up、4/Paeth），需要先还原过滤才能得到原始的像素值。

图片的 100 行像素中，只有前 3 行包含有效数据，第 4\~100 行全黑。

### 6. 反过滤恢复像素

对前 3 行分别按对应的 filter 类型进行逆运算：

Row 0: Filter 1 (Sub) — raw[x] = filtered[x] + raw[x-1]

Row 1: Filter 4 (Paeth) — raw[x] = filtered[x] + PaethPredictor(...)

Row 2: Filter 4 (Paeth) — raw[x] = filtered[x] + PaethPredictor(...)

恢复后得到 300 个原始像素（3 行 × 100 列）。

### 7. 提取 LSB

每个像素的 RGB 值都只有两种取值，相差刚好为 1：

  ---------- ------------------ ------------------
  **通道**   **值 1 (bit=0)**   **值 2 (bit=1)**
  R          72 (H)             73 (I)
  G          108 (l)            109 (m)
  B          136                137
  ---------- ------------------ ------------------

提取每个通道的 LSB，共 300 × 3 = 900 bits，按 MSB 优先分组为 112 字节，得到 flag。

### 8. Flag

ISCC{1d3f1c4t10gn_1s_Eth3_k3yl_t0_ivT1ct0ry}

EXP：
=====

（1）
-----

from scapy.all import *

PCAP_PATH = r'C:\\Users\\ericgao\\Desktop\\test\\ISCC区域\\attachment-17.pcapng'

pkts = rdpcap(PCAP_PATH)

udp_pkts = [p for p in pkts if UDP in p]

tcp_pkts = [p for p in pkts if TCP in p]

print(f'总包数: {len(pkts)}')

print(f'UDP 包: {len(udp_pkts)}')

print(f'TCP 包: {len(tcp_pkts)}')

# UDP: 目标为 239.255.255.250:1900 的 SSDP 包

print('\\n=== UDP 流量（前 5 包）===')

for pkt in udp_pkts[:5]:

print(f' {pkt[IP].src}:{pkt[UDP].sport} -&gt; {pkt[IP].dst}:{pkt[UDP].dport}')

# TCP: 目标为 45.78.1.1:80 的 C2 通信

print('\\n=== TCP 流量 ===')

for pkt in tcp_pkts:

src = f'{pkt[IP].src}:{pkt[TCP].sport}'

dst = f'{pkt[IP].dst}:{pkt[TCP].dport}'

flags = pkt[TCP].flags

flag_str = []

if flags & 0x02: flag_str.append('SYN')

if flags & 0x10: flag_str.append('ACK')

if flags & 0x08: flag_str.append('PSH')

if flags & 0x01: flag_str.append('FIN')

print(f' {src} -&gt; {dst} [{",".join(flag_str)}]')

（2）
-----

from scapy.all import *

PCAP_PATH = r'C:\\Users\\ericgao\\Desktop\\test\\ISCC区域\\attachment-17.pcapng'

pkts = rdpcap(PCAP_PATH)

udp_pkts = [p for p in pkts if UDP in p]

tcp_pkts = [p for p in pkts if TCP in p]

print(f'总包数: {len(pkts)}')

print(f'UDP 包: {len(udp_pkts)}')

print(f'TCP 包: {len(tcp_pkts)}')

# 输出所有 UDP 包内容

print('\\n=== UDP 流量内容 ===')

for i, pkt in enumerate(udp_pkts):

if Raw in pkt:

print(f'[{i}] {bytes(pkt[Raw].load).decode()}')

# 输出所有 TCP 包内容

print('\\n=== TCP 流量内容 ===')

for i, pkt in enumerate(tcp_pkts):

src = f'{pkt[IP].src}:{pkt[TCP].sport}'

dst = f'{pkt[IP].dst}:{pkt[TCP].dport}'

flags = pkt[TCP].flags

flag_str = []

if flags & 0x02: flag_str.append('SYN')

if flags & 0x10: flag_str.append('ACK')

if flags & 0x08: flag_str.append('PSH')

if flags & 0x01: flag_str.append('FIN')

payload = f' | {bytes(pkt[Raw].load).decode(errors="ignore")}' if Raw in pkt else ''

print(f'[{i}] {src} -&gt; {dst} [{",".join(flag_str)}]{payload}')
