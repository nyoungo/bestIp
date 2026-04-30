import socket
import re
import time
import threading
from queue import Queue
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Cloudflare节点测试配置参数
TEST_TIMEOUT = 3  # 测试超时时间(秒)
TEST_PORT = 443   # 测试端口
MAX_THREADS = 3  # 最大线程数
TOP_NODES = 9    # 显示和保存前N个最快节点
TXT_OUTPUT_FILE = "bestIp.txt"    # TXT结果保存文件

# 国家代码到中文国家名称的映射
COUNTRY_CODES = {
    'US': '美国',
    'CN': '中国',
    'JP': '日本',
    'SG': '新加坡',
    'KR': '韩国',
    'GB': '英国',
    'FR': '法国',
    'DE': '德国',
    'AU': '澳大利亚',
    'CA': '加拿大',
    'HK': '中国香港',
    'TW': '中国台湾',
    'IN': '印度',
    'RU': '俄罗斯',
    'BR': '巴西',
    'MX': '墨西哥',
    'NL': '荷兰',
    'SE': '瑞典',
    'CH': '瑞士',
    'IT': '意大利',
    'ES': '西班牙',
    'Unknown': '未知'
}

# IP地理位置查询函数
def get_ip_country(ip):
    """获取IP地址对应的国家信息(返回中文)"""
    try:
        # 验证IP格式
        socket.inet_aton(ip)
        
        # 创建会话并配置重试机制
        import requests
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        # 尝试使用ipwhois.app API (不需要API密钥)
        try:
            url = f"https://ipwhois.app/json/{ip}"
            response = session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if 'country' in data and data['country']:
                    country = data['country']
                    # 转换国家名称为中文
                    if country == 'United States':
                        return '美国'
                    elif country == 'China':
                        return '中国'
                    elif country == 'Japan':
                        return '日本'
                    elif country == 'Singapore':
                        return '新加坡'
                    elif country == 'South Korea':
                        return '韩国'
                    elif country == 'United Kingdom':
                        return '英国'
                    elif country == 'France':
                        return '法国'
                    elif country == 'Germany':
                        return '德国'
                    elif country == 'Australia':
                        return '澳大利亚'
                    elif country == 'Canada':
                        return '加拿大'
                    elif country == 'Hong Kong':
                        return '中国香港'
                    elif country == 'Taiwan':
                        return '中国台湾'
                    # 如果是国家代码，尝试从映射中获取中文名称
                    elif len(country) == 2:
                        return COUNTRY_CODES.get(country, country)
                    return country
        except Exception as e:
            print(f"ipwhois.app错误 {ip}: {str(e)}")
        
        # 尝试使用ip-api.com的备用端点 (使用HTTP而非HTTPS)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=countryCode"
            response = session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success' and 'countryCode' in data:
                    country_code = data['countryCode']
                    # 从映射中获取中文国家名称
                    return COUNTRY_CODES.get(country_code, country_code)
        except Exception as e:
            print(f"ip-api.com错误 {ip}: {str(e)}")
        
        # 基于IP地址范围的简单判断 (Cloudflare IP范围)
        # 这些IP看起来是Cloudflare的IP地址
        octets = ip.split('.')
        if octets[0] == '104' and octets[1] == '18':
            return '美国'  # Cloudflare US IPs
        elif octets[0] == '108' and octets[1] == '162':
            return '美国'  # Cloudflare US IPs
        elif octets[0] == '162' and octets[1] == '159':
            return '美国'  # Cloudflare US IPs
        elif octets[0] == '172' and octets[1] == '64':
            return '美国'  # Cloudflare US IPs
        
        return '未知'
    except Exception as e:
        print(f"IP验证错误 {ip}: {str(e)}")
        return '未知'

def clean_ip(ip_str):
    """清理IP字符串，移除可能的冒号或其他字符"""
    # 移除末尾的冒号和空格
    ip_str = ip_str.strip().rstrip(':')
    # 验证是否为有效的IPv4地址
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(pattern, ip_str):
        # 进一步验证每个数字是否在0-255范围内
        parts = ip_str.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return ip_str
    return None

# Cloudflare节点测试类
class CloudflareNodeTester:
    def __init__(self):
        self.nodes = set()  # 存储节点IP，使用set避免重复
        self.results = []   # 存储测试结果
        self.lock = threading.Lock()
    
    def fetch_known_nodes(self):
        """从公开来源获取已知的Cloudflare节点IP"""

        
        # 常见的Cloudflare IP段
        ip_ranges = [
'104.24.0.0/16',
'103.21.244.0/22',
'103.31.4.0/22',
'45.64.64.0/22',
'104.28.0.0/16',
'188.114.96.0/24',
'188.114.97.0/24',
'104.22.0.0/16',
'104.25.0.0/16',
        ]
        
        # 从IP段生成部分IP示例
        for ip_range in ip_ranges:
            base_ip, cidr = ip_range.split('/')
            octets = base_ip.split('.')
            
            # 生成该网段的一些示例IP
            for i in range(1, 20):  # 每个网段生成9个示例IP
                ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{i + int(octets[3])}"
                self.nodes.add(ip)
        
    
    def test_node_speed(self, ip):
        """测试单个节点的连接速度"""
        try:
            start_time = time.time()
            # 创建socket连接
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TEST_TIMEOUT)
                result = s.connect_ex((ip, TEST_PORT))
                if result == 0:  # 连接成功
                    response_time = (time.time() - start_time) * 1000  # 转换为毫秒
                    return {
                        'ip': ip,
                        'reachable': True,
                        'response_time_ms': int(response_time),
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    return {
                        'ip': ip,
                        'reachable': False,
                        'response_time_ms': None,
                        'timestamp': datetime.now().isoformat()
                    }
        except Exception as e:
            return {
                'ip': ip,
                'reachable': False,
                'response_time_ms': None,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def worker(self, queue):
        """线程工作函数"""
        while not queue.empty():
            ip = queue.get()
            try:
                result = self.test_node_speed(ip)
                with self.lock:
                    self.results.append(result)
                    # 每完成360个测试，打印进度
                    if len(self.results) % 360 == 0:
                        print(f"已测试 {len(self.results)}/{len(self.nodes)} 个")
            finally:
                queue.task_done()
    
    def test_all_nodes(self):
        """测试所有节点的速度"""

        
        # 创建任务队列
        queue = Queue()
        for ip in self.nodes:
            queue.put(ip)
        
        # 启动线程
        threads = []
        for _ in range(min(MAX_THREADS, len(self.nodes))):
            thread = threading.Thread(target=self.worker, args=(queue,))
            thread.start()
            threads.append(thread)
        
        # 等待所有线程完成
        for thread in threads:
            thread.join()
        

    
    def sort_and_display_results(self):
        """排序并显示测试结果，包含中文国家信息"""
        # 过滤出可连接的节点并按响应时间排序
        reachable_nodes = [
            node for node in self.results 
            if node['reachable'] and node['response_time_ms'] is not None
        ]
        
        # 按响应时间升序排序(最快的在前)
        sorted_nodes = sorted(
            reachable_nodes, 
            key=lambda x: x['response_time_ms']
        )
        
        
        # 显示前N个最快节点，包含中文国家信息
        for i, node in enumerate(sorted_nodes[:TOP_NODES], 1):
            country = get_ip_country(node['ip'])
            print(f"{node['ip']}#{country}")
        
        return sorted_nodes
    
    def save_results(self, results):
        """只保存前30名结果到TXT文件，并显示中文国家信息"""
        try:
            # 只取前30名结果
            top_results = results[:20]  # 明确只取前30名
            
            with open(TXT_OUTPUT_FILE, 'w', encoding='utf-8') as f:
                # 清空文件并只写入前30个结果
                for i, node in enumerate(top_results):
                    # 获取IP的国家信息（已经是中文）
                    country = get_ip_country(node['ip'])
                    line = f"{node['ip']}#{country}\n"
                    f.write(line)
            
        except Exception as e:
            print(f"保存结果失败: {e}")

# Cloudflare节点测试功能
def test_cloudflare_nodes():
    """运行Cloudflare节点测试"""
    print("\n===== Cloudflare节点测速工具 =====")
    tester = CloudflareNodeTester()
    tester.run()

# CloudflareNodeTester类的run方法
def run_cloudflare_tester(self):
    """运行整个测试流程"""
    start_time = time.time()
    
    # 1. 获取节点
    self.fetch_known_nodes()
    
    # 2. 测试所有节点
    self.test_all_nodes()
    
    # 3. 排序并显示结果
    sorted_nodes = self.sort_and_display_results()
    
    # 4. 保存结果
    self.save_results(sorted_nodes)
    
    total_time = int(time.time() - start_time)

# 添加run方法到CloudflareNodeTester类
CloudflareNodeTester.run = run_cloudflare_tester

# 主函数 - 直接执行Cloudflare节点测试
if __name__ == "__main__":

    try:
        # 直接执行Cloudflare节点测试
        tester = CloudflareNodeTester()
        tester.run()
        
    except KeyboardInterrupt:
        print("\n用户中断了程序")
    except Exception as e:
        print(f"程序出错: {e}")


