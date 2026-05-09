========================================
  ISCC 附件-17 — CTF Misc Writeup
========================================

Flag: ISCC{1dR3Df1c4t10Hn_1s_XthJ3_k3y_t0_v1ct0ry}

附件: attachment-17.pcapng

----------------------------------------
  一、题目概述
----------------------------------------

网络管理员抓取到了一段可疑的网络流量，其中绝大部分是某台被攻陷的摄像头
在持续广播的垃圾组播流量。攻击者的秘密指令隐藏在嘈杂的信号中。

提示：声东击西（三十六计第一套第六计），在那些看似无意义的广播中，
藏着打开真正宝藏的钥匙。

----------------------------------------
  二、分析链（5 个步骤）
----------------------------------------

步骤 1：流量包分类
  - 1500 个 UDP 组播包：192.168.1.100 → 239.255.255.250:1900（SSDP噪声）
    · 每个包 payload 为 28 字节 base64 字符串，源端口随机
  - 9 个 TCP 包：192.168.1.100:12345 ↔ 45.78.1.1:80（真实攻击）
    · 三次握手 + HTTP POST 请求

步骤 2：提取 HTTP POST 中的加密 ZIP
  - TCP 流中有一个 800 字节的数据包，包含 HTTP POST 请求：
      POST /command HTTP/1.1
      Host: 45.78.1.1
      Content-Type: application/json

      {"instruction": "<base64编码的ZIP>", "note": "This is the real command."}
  - base64 解码得到 AES-256 加密的 ZIP 文件（compression method 99）
  - ZIP 内含 image.png（481 字节，被加密）

步骤 3：从广播噪声中提取密码
  - 1500 个 UDP 包中，有 14 个源端口出现了两次（重复端口）
  - 端口 2800 的第二个包（index=800）payload 异常：
      payload = U2hlbmdEb25nSmlYaUAzNi0xLTY=
  - 该 payload 以 "=" 结尾，区别于其他随机 base64 数据
  - 解码：U2hlbmdEb25nSmlYaUAzNi0xLTY= → ShengDongJiXi@36-1-6
  - 含义：声东击西@36计-第1套-第6计

步骤 4：AES-256 解密 ZIP
  - 密码：ShengDongJiXi@36-1-6
  - ZIP 使用 WinZip AES-256-CTR 加密格式
  - 解密流程：
    · 提取 16 字节 salt
    · PBKDF2-SHA1（1000轮）派生 66 字节密钥材料
    · 前 32 字节为 AES 密钥，后 2 字节为密码验证值
    · 验证通过后，AES-256-CTR 解密数据
    · deflate 解压得到 image.png

步骤 5：LSB 隐写提取 Flag
  - image.png 为 100×100 RGB 图片，肉眼看似纯色
  - 分析发现仅有 8 种颜色，RGB 各通道仅在 LSB 上有差异：
      R: 72 或 73（LSB = 0 或 1）
      G: 108 或 109（LSB = 0 或 1）
      B: 136 或 137（LSB = 0 或 1）
  - 经典 LSB 隐写术，提取所有像素所有通道的最低有效位
  - 每 8 bit 组成一个字节，得到 flag

----------------------------------------
  三、利用步骤
----------------------------------------

Step 1: 解析 pcap，分离 UDP 组播包和 TCP 流
Step 2: 从 TCP 流的 HTTP POST 提取 base64 编码的加密 ZIP
Step 3: 在 1500 个 UDP 包中找到重复端口 2800 的特殊包
Step 4: 解码密码 ShengDongJiXi@36-1-6
Step 5: 使用密码解密 ZIP 得到 image.png
Step 6: LSB 隐写提取 flag

----------------------------------------
  四、解题脚本
----------------------------------------

import struct, base64, hashlib, zlib, json
from collections import Counter

# ===== 解析 PCAP =====
with open("attachment-17.pcapng", "rb") as f:
    data = f.read()

pos = 24
packets_28 = []
http_payload = None

while pos < len(data):
    if pos + 16 > len(data): break
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', data[pos:pos+16])
    pos += 16
    if pos + incl_len > len(data): break
    pkt = data[pos:pos+incl_len]
    pos += incl_len
    ihl = (pkt[0] & 0x0f) * 4
    src_port = struct.unpack('>H', pkt[ihl:ihl+2])[0]
    payload = pkt[ihl+8:].rstrip(b'\x00')
    if len(pkt[ihl+8:]) == 28:
        packets_28.append({'src_port': src_port, 'payload': payload})
    elif len(pkt[ihl+8:]) == 800:
        http_payload = payload

# ===== 提取密码 =====
port_counter = Counter(p['src_port'] for p in packets_28)
for p in packets_28:
    if port_counter[p['src_port']] > 1 and p['payload'].endswith(b'='):
        password = base64.b64decode(p['payload'])
        break
# password = b'ShengDongJiXi@36-1-6'

# ===== 提取加密 ZIP =====
http_text = http_payload.decode('utf-8', errors='replace')
json_data = json.loads(http_text[http_text.find('{'):])
zip_data = base64.b64decode(json_data['instruction'])

# ===== AES-256-CTR 解密 =====
fname_len = struct.unpack('<H', zip_data[26:28])[0]
extra_len = struct.unpack('<H', zip_data[28:30])[0]
comp_size = struct.unpack('<I', zip_data[18:22])[0]
data_start = 30 + fname_len + extra_len
salt = zip_data[data_start:data_start+16]
derived = hashlib.pbkdf2_hmac('sha1', password, salt, 1000, dklen=66)
aes_key = derived[:32]
enc_data = zip_data[data_start+18:data_start+comp_size-10]
# AES-256-CTR 解密 enc_data（需要 AES 库）
# decompressed = zlib.decompress(decrypted, -15)

# ===== LSB 提取 =====
# 解析 PNG 像素后：
# lsb_bits = [pixel_value & 1 for each channel of each pixel]
# flag_bytes = [bits_to_byte(lsb_bits[i:i+8]) for i in range(0, len, 8)]
# → ISCC{1dR3Df1c4t10Hn_1s_XthJ3_k3y_t0_v1ct0ry}

----------------------------------------
  五、Flag
----------------------------------------

  ISCC{1dR3Df1c4t10Hn_1s_XthJ3_k3y_t0_v1ct0ry}

----------------------------------------
  六、知识点总结
----------------------------------------

  1. PCAP 流量分析：识别 UDP 组播噪声 vs TCP 真实攻击流量
  2. 隐蔽信道：重复源端口作为标记，隐藏密钥于噪声中
  3. WinZip AES-256 加密：method 99、PBKDF2 密钥派生、CTR 模式
  4. LSB 隐写术：从 RGB 图片最低有效位提取隐藏信息
  5. 文化知识：三十六计"声东击西"作为密码线索
