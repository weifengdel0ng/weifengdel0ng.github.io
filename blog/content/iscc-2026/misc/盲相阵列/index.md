+++
title = "盲相阵列"
date = "2026-05-14"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

Misc-盲相阵列

解题思路（必须包含文字说明+截图）

1\. 附件分析

压缩包内包含 array_iq.csv 和 rx_note.txt。提示给出采样率 48000 Hz、符号率 1200 baud、残余频偏约 +1700 Hz，并明确数据链路为 PN mask -&gt; 16-lane column DMA -&gt; H(7,4) nibbles -&gt; BP1 frame。

2\. 信号解调

由 48000 / 1200 = 40 可知每个符号有 40 个采样点。对复数 I/Q 样本做 -1700 Hz 频偏校正，枚举 0..39 的符号边界后，最佳符号偏移为 17。

对每 40 个采样求平均得到符号，再用前 80 个符号估计公共相位，完成 BPSK 判决。前 64 bit 是 1010... 训练序列，后 16 bit 是同步字 0xE5A2。

3\. 去 PN、DMA 复原与纠错

训练块后的 560 bit 是有效载荷，正好对应 80 个 Hamming(7,4) 码字。对 PN 参数、DMA 顺序和 Hamming 解码方式进行搜索，以 BP1 帧头、低纠错距离和 CRC32 作为判据。

最终命中的参数为：PN8，seed=0xA5，mask=0x1D，右移，输出 MSB。

DMA 为 16-lane column-major 转回 row-major，即 depn.reshape(16, 35).T.reshape(-1)。

Hamming(7,4) 采用标准布局 [p1, p2, d1, p4, d2, d3, d4]，总共修正 5 bit。

4\. BP1 帧与 CRC 校验

恢复出的帧十六进制为：

42503120495343437b523721715f5a40346d5e54393f702456256b26322a6e7e4c23787da60a993c

其中 42 50 31 为字符串 BP1，长度字节为 0x20，表示后续 payload 长度 32，帧尾 a6 0a 99 3c 为大端 CRC32。

对 payload ISCC{R7!q_Z@4m\^T9?p\$V%k&2*n\~L\#x} 计算 CRC32，结果为 0xA60A993C，与帧尾一致，校验通过。

5\. 最终结果

Flag: ISCC{R7!q_Z@4m\^T9?p\$V%k&2*n\~L\#x}

Exp（如有，请粘贴完整代码，不允许截图！）

from pathlib import Path

import zlib

import numpy as np

CSV_PATH = Path(r"blind-phase\\bundle\\array_iq.csv")

def pn8_mask(length: int, seed: int = 0xA5, mask: int = 0x1D) -&gt; np.ndarray:

state = seed & 0xFF

out = np.empty(length, dtype=np.uint8)

for i in range(length):

out[i] = (state &gt;&gt; 7) & 1

fb = (state & mask).bit_count() & 1

state = ((state &gt;&gt; 1) | (fb &lt;&lt; 7)) & 0xFF

return out

def hamming74_decode(bits: np.ndarray) -&gt; tuple[list[int], int]:

codebook = []

for nib in range(16):

d1 = (nib &gt;&gt; 3) & 1

d2 = (nib &gt;&gt; 2) & 1

d3 = (nib &gt;&gt; 1) & 1

d4 = nib & 1

codebook.append((

np.array([d1 \^ d2 \^ d4, d1 \^ d3 \^ d4, d1, d2 \^ d3 \^ d4, d2, d3, d4], dtype=np.uint8),

nib,

))

nibbles = []

corrections = 0

for i in range(0, len(bits), 7):

cw = bits[i:i + 7]

dist, nib = min((int(np.count_nonzero(cw != code)), nib) for code, nib in codebook)

corrections += dist

nibbles.append(nib)

return nibbles, corrections

def main() -&gt; None:

samples = np.loadtxt(CSV_PATH, delimiter=",", skiprows=1, usecols=(1, 2))

x = samples[:, 0] + 1j * samples[:, 1]

fs = 48_000

sps = 40

freq_offset = 1_700

symbol_offset = 17

n = np.arange(len(x))

corrected = x * np.exp(-1j * 2 * np.pi * freq_offset * n / fs)

symbols = corrected[symbol_offset:symbol_offset + ((len(corrected) - symbol_offset) // sps) * sps]

symbols = symbols.reshape(-1, sps).mean(axis=1)

phase = 0.5 * np.angle(np.sum(symbols[:80] ** 2))

symbols *= np.exp(-1j * phase)

bits = (symbols.real &lt; 0).astype(np.uint8)

payload = bits[80:640]

depn = payload \^ pn8_mask(len(payload))

# 16-lane column DMA: received column-major stream back to row-major order.

code_bits = depn.reshape(16, 35).T.reshape(-1)

nibbles, corrections = hamming74_decode(code_bits)

frame = bytes((nibbles[i] &lt;&lt; 4) | nibbles[i + 1] for i in range(0, len(nibbles), 2))

length = frame[3]

flag = frame[4:4 + length]

crc_expected = int.from_bytes(frame[-4:], "big")

crc_actual = zlib.crc32(flag) & 0xFFFFFFFF

print(f"frame={frame.hex()}")

print(f"corrections={corrections}")

print(f"crc_ok={crc_actual == crc_expected}")

print(flag.decode())

if __name__ == "__main__":

main()
