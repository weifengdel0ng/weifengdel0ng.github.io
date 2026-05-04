+++
title = "rc4"
date = "2025-12-17"
type = "post"
categories = ["Reverse"]
tags = ["Reverse"]
draft = false
+++
import base64  
  
  
def rc4_decrypt(cipher_data, key_bytes):  
    """  
    RC4 解密函数（严格匹配反汇编逻辑）  
    :param cipher_data: 密文（bytes类型）  
    :param key_bytes: 原始16字节密钥（bytes类型）  
    :return: 明文（bytes类型）  
    """    # === 1. RC4 KSA 阶段（对应 sub_1400015D0） ===    S = list(range(256))  # 对应 byte_140013140（S盒）  
    j = 0  
    key_len = len(key_bytes)  # 固定为16  
  
    # 模拟反汇编中"循环填充密钥+S盒置换"逻辑  
    for i in range(256):  
        # 反汇编：byte_140013040[n256] = Str[n256 % 16]  
        key_byte = key_bytes[i % key_len]  
        # 反汇编：v2 = (unsigned __int8)(v2 + v4 + *v3++)  
        j = (j + S[i] + key_byte) % 256  
        # 交换 S[i] 和 S[j]        S[i], S[j] = S[j], S[i]  
  
    # === 2. RC4 PRGA 阶段（对应 sub_140001670） ===    i = 0  
    j = 0  
    plain_bytes = []  
  
    for byte in cipher_data:  
        i = (i + 1) % 256  
        v7 = S[i]  
        j = (j + v7) % 256  
        S[i], S[j] = S[j], S[i]  
        t = (S[i] + v7) % 256  
        keystream_byte = S[t]  
        # 异或解密（核心操作）  
        plain_byte = byte ^ keystream_byte  
        plain_bytes.append(plain_byte)  
  
    return bytes(plain_bytes)  
  
  
def parse_cipher_input(input_str, input_type):  
    """解析密文输入为bytes（兼容多格式）"""  
    try:  
        if input_type == 1:  
            # 十六进制字符串（支持0x前缀/空格）  
            input_str = input_str.strip().replace("0x", "").replace(" ", "")  
            return bytes.fromhex(input_str)  
        elif input_type == 2:  
            # Base64编码  
            return base64.b64decode(input_str)  
        elif input_type == 3:  
            # UTF-8字符串  
            return input_str.encode("utf-8")  
        elif input_type == 4:  
            # GBK字符串（兼容中文）  
            return input_str.encode("gbk")  
        else:  
            raise ValueError("无效的输入类型")  
    except Exception as e:  
        raise RuntimeError(f"密文解析失败：{str(e)}")  
  
  
if __name__ == "__main__":  
    # ===================== 核心：原始16字节密钥 =====================    # 对应反汇编中的 string2 原始密钥：26 26 E8 48 54 46 18 97 43 A9 46 9A 37 D0 0F 13  
    RC4_KEY_BYTES = bytes.fromhex("26 26 E8 48 54 46 18 97 43 A9 46 9A 37 D0 0F 13")  
  
    print("=== RC4 解密工具（精准匹配反汇编密钥） ===")  
    print("密文输入类型：")  
    print("1 - 十六进制字符串（例：9a0f8e14b93b87081e89）")  
    print("2 - Base64 编码字符串（例：maq+FLk7hwh6iQ==）")  
    print("3 - 原始字符串（UTF-8 编码）")  
    print("4 - 原始字符串（GBK 编码）")  
  
    # 获取输入类型（防错）  
    while True:  
        try:  
            input_type = int(input("\n请选择密文类型（1-4）："))  
            if input_type not in [1, 2, 3, 4]:  
                print("请输入1-4之间的数字！")  
                continue  
            break        except ValueError:  
            print("请输入有效数字！")  
  
    # 获取密文内容  
    cipher_input = input("请输入密文内容：").strip()  
  
    # 执行解密  
    try:  
        cipher_data = parse_cipher_input(cipher_input, input_type)  
        plain_data = rc4_decrypt(cipher_data, RC4_KEY_BYTES)  
  
        # 多编码输出明文（避免乱码）  
        print("\n=== 解密结果 ===")  
        print(f"明文（原始bytes）：{plain_data}")  
        # 尝试常见编码解码  
        for encoding in ["utf-8", "gbk", "latin-1", "ascii"]:  
            try:  
                print(f"明文（{encoding} 解码）：{plain_data.decode(encoding)}")  
            except (UnicodeDecodeError, LookupError):  
                continue  
        print(f"明文（十六进制）：{plain_data.hex()}")  
  
    except Exception as e:  
        print(f"\n解密失败：{str(e)}")
