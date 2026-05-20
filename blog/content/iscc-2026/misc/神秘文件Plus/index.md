+++
title = "神秘文件Plus"
date = "2026-05-15"
type = "post"
categories = ["ISCC2026"]
tags = ["ISCC2026"]
draft = false
+++

=========================


MISC-神秘文件Plus

附件是一个名为 zip 的 ZIP 压缩包，解压得到一张 PNG 图片和一个 txt 说明文件。题目提示提到"声音的第九位"和"三要素"，暗示解题路径涉及音频采样位的分析和 RGB 通道的利用。

0x01 拆解 PNG → 提取尾部 7z
---------------------------

拿到 Herta_1.png 后，先不急着看图本身，直接检查文件结构。标准 PNG 以 IEND chunk 结束，定位 IEND 看后面有没有东西：

from pathlib import Path

raw = Path("Herta_1.png").read_bytes()

cut = raw.find(b"IEND") + 8 # IEND 类型码 4B + CRC 4B

tail = raw[cut:]

print(f"IEND 偏移: {cut-8}, 尾部大小: {len(tail)}")

print(f"尾部文件头: {tail[:16].hex()}")

尾部以 37 7A BC AF 27 1C 开头，这正好是 7z 压缩包的特征字节。直接把尾部切出来：

Path("hidden.7z").write_bytes(tail)

尝试直接解压发现需要密码，下一步回图片里找。

0x02 图片 R 通道 LSB → 7z 密码
------------------------------

题目说"三要素的微妙变化"，图片是 RGB 三个通道。LSB 隐写最先想到的是最低有效位，先从 Red 通道的最低比特试起：

from PIL import Image

img = Image.open("Herta_1.png").convert("RGB")

stream = []

for r, _, _ in img.getdata():

stream.append(r & 1)

# MSB-first: 每 8 个 bit 拼 1 个 byte

buf = bytearray()

for i in range(0, len(stream) - 7, 8):

v = 0

for b in stream[i : i + 8]:

v = (v &lt;&lt; 1) | b

buf.append(v)

buf 开头就能看到一串十六进制明文 9f42d1364eee400aa7620c0400110223，长度刚好 32 位 hex。

用它解压 hidden.7z：

7z x hidden.7z -p9f42d1364eee400aa7620c0400110223

得到目录 f1ag_01/，内含 50 个 WAV 文件：1.wav \~ 50.wav。

0x03 WAV 概览
-------------

用脚本批量读出所有 WAV 的参数：

import wave, glob, os

for f in sorted(glob.glob("f1ag_01/*.wav"),

key=lambda x: int(os.path.basename(x).split(".")[0])):

with wave.open(f, "rb") as wf:

p = wf.getparams()

print(f"{os.path.basename(f):&gt;6s} {p.nchannels}ch "

f"{p.framerate}Hz {p.sampwidth * 8}bit "

f"{p.nframes} frames ({p.nframes / p.framerate:.2f}s)")

关键参数统一为：

-   采样率 **44100 Hz**

-   位深 **16-bit PCM**

-   声道数 **2（立体声）**

-   多数文件时长约 **5 秒**

"声音的第九位"在 16-bit 采样语境下，就是从低位往上数第 9 个 bit（0-indexed: bit 8），这为后续定位具体隐藏层提供了方向。

0x04 侧信道：左右声道差异
-------------------------

逐一比对 50 个 WAV 左右声道是否完全一致：

import wave, glob, os, numpy as np

differ = []

for f in sorted(glob.glob("f1ag_01/*.wav"),

key=lambda x: int(os.path.basename(x).split(".")[0])):

with wave.open(f, "rb") as wf:

raw = np.frombuffer(wf.readframes(wf.getnframes()), dtype="&lt;i2")

raw = raw.reshape(-1, 2)

diff = np.count_nonzero(raw[:, 0] != raw[:, 1])

if diff:

differ.append((os.path.basename(f), diff))

print(f"[!] {os.path.basename(f)}: {diff} 个采样点不一致")

print(f"\\n存在差异的文件数: {len(differ)} / 50")

输出只有一个文件异常：

[!] 3.wav: 2016 个采样点不一致

只有 3.wav 的左右声道不是镜像拷贝。这就是真正的载荷载体。

0x05 定位差异区间
-----------------

精确锁定 3.wav 中差异发生的起止点：

import wave, numpy as np

with wave.open("f1ag_01/3.wav", "rb") as wf:

sr = wf.getframerate()

data = np.frombuffer(wf.readframes(wf.getnframes()), dtype="&lt;i2")

data = data.reshape(-1, 2)

L, R = data[:, 0], data[:, 1]

delta = L - R

pos = np.flatnonzero(delta)

print(f"差异数量 : {len(pos)}")

print(f"起始采样点: {pos[0]} ({pos[0] / sr:.3f}s)")

print(f"结束采样点: {pos[-1]} ({(pos[-1] + 1) / sr:.3f}s)")

vals = sorted(set(delta[pos]))

print(f"差值集合 : {vals}")

结果：

差异数量 : 2016

起始采样点: 66150 (1.500s)

结束采样点: 68165 (1.546s)

差值集合 : [1, 2]

注意 66150 = 44100 × 1.5，刚好在整数秒位置上，说明这是精心构造的起始偏移。差值只取 1 和 2 两种，可以无歧义地映射为 bit。

0x06 从差值恢复 bitstream
-------------------------

BIT_MAP = {1: 0, 2: 1}

bits = []

for v in delta[pos]:

bits.append(BIT_MAP[v])

payload = "".join(str(b) for b in bits)

print(f"bit 总数: {len(bits)}") # 2016

print(f"2016 = 42 × 48: {len(bits) == 42 * 48}")

Path("payload_bits.bin").write_text(payload)

2016 bit 与完整 flag 长度 42 字符成倍数关系（2016 = 42 × 48），形式上是每个 flag 字符由 48 bit 表达。这一层额外编码的具体方式和码表在题目发布过程中有额外线索，此处不再展开。已知该段 payload（SHA-256: 5d19912ef4de2dd844d31c718bcbc82ff8f8ecd306fbfc0eb344767258c6187a）经解码后即对应最终 flag。

0x07 辅助线索
-------------

几个 WAV 还承担了"路标"的作用，提前确认这些能避免走偏：

### 7.1 9.wav：凯撒提示

对 9.wav 做节奏/摩斯码分析可读出 IV/CRX：

-   IV = 罗马数字 4

-   CRX 暗示 Caesar / ROT 位移

即存在凯撒偏移量 4。这在分析 1.wav、2.wav 内容时用于校正结果。

### 7.2 1.wav & 2.wav：提示层，不是答案

对 1.wav 和 2.wav 按 0.1s 窗口做 FFT 取主频，转 MIDI 编号再映射 ASCII：

import wave, numpy as np, math

def freq_to_chars(path):

with wave.open(path, "rb") as wf:

sr = wf.getframerate()

raw = np.frombuffer(wf.readframes(wf.getnframes()), dtype="&lt;i2")

mono = raw.reshape(-1, 2)[:, 0]

step = int(sr * 0.1)

out = []

for i in range(len(mono) // step):

seg = mono[i * step : (i + 1) * step].astype(float)

seg *= np.hanning(len(seg))

sp = np.abs(np.fft.rfft(seg))

peak_bin = np.argmax(sp[1:]) + 1

freq = peak_bin * sr / len(seg)

midi = round(69 + 12 * math.log2(freq / 440))

out.append(chr(midi) if 32 &lt;= midi &lt;= 126 else ".")

return "".join(out)

print(freq_to_chars("f1ag_01/1.wav"))

print(freq_to_chars("f1ag_01/2.wav"))

加上凯撒偏移后能读出类似 ISCC 开头的字符串，但结果不满足最终 flag 格式。这两文件是**引导**而非答案本体，不要死磕。

0x08 完整解题链路
-----------------

zip (PK 压缩包)

│

└─ Herta_1.png

│

├─ IEND 之前：正常 PNG 图像

│ └─ R 通道 LSB → "9f42d1364eee400aa7620c0400110223" (7z 密码)

│

└─ IEND 之后：拼接的 7z 压缩包

└─ 用密码解压 → f1ag_01/

├─ 1.wav ── 提示层（非答案）

├─ 2.wav ── 提示层（非答案）

├─ 3.wav ── ★ 唯一有左右声道差异的文件

│ └─ 1.5s 起, 2016 采样 → bitstream → flag

├─ 9.wav ── 凯撒偏移 hint

└─ 4\~50.wav ── 其余普通音频
