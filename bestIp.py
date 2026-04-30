import socket
import re
import time
import threading
import subprocess
from queue import Queue
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ==================== 配置参数 ====================
TEST_TIMEOUT = 3            # TCP 连接超时(秒)
TEST_PORT = 443             # 测试端口
MAX_THREADS = 5             # 最大线程数(调高以加快初次延迟测试)
CANDIDATE_COUNT = 30        # 延迟测试后选取前多少个节点进行详细测试
TOP_NODES = 9               # 最终显示和保存的前N个最快节点

# 丢包测试参数
ENABLE_LOSS_TEST = True
PING_COUNT = 4              # 每次 ping 发送包数
PING_TIMEOUT = 2            # 单个 ping 超时(秒)

# 下载速度测试参数
ENABLE_SPEED_TEST = True
SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=1048576"  # 1MB
SPEED_TEST_TIMEOUT = 10     # 下载超时(秒)

# 综合评分权重 (归一化后加权)
WEIGHT_LATENCY = 0.4        # 延迟权重
WEIGHT_LOSS = 0.3           # 丢包率权重 (丢包率越低越好)
WEIGHT_SPEED = 0.3          # 下载速度权重 (速度越快越好)

TXT_OUTPUT_FILE = "bestIp.txt"

# 国家代码映射 (与原脚本一致)
COUNTRY_CODES = {
    'US': '美国', 'CN': '中国', 'JP': '日本', 'SG': '新加坡', 'KR': '韩国',
    'GB': '英国', 'FR': '法国', 'DE': '德国', 'AU': '澳大利亚', 'CA': '加拿大',
    'HK': '中国香港', 'TW': '中国台湾', 'IN': '印度', 'RU': '俄罗斯',
    'BR': '巴西', 'MX': '墨西哥', 'NL': '荷兰', 'SE': '瑞典', 'CH': '瑞士',
    'IT': '意大利', 'ES': '西班牙', 'Unknown': '未知'
}

# ==================== 辅助函数 ====================
def get_ip_country(ip):
    """获取 IP 对应的中文国家名称 (与原脚本相同)"""
    try:
        socket.inet_aton(ip)
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500,502,503,504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        # 优先 ipwhois.app
        try:
            url = f"https://ipwhois.app/json/{ip}"
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if 'country' in data and data['country']:
                    country = data['country']
                    # 常见英文名转中文
                    eng_to_cn = {
                        'United States': '美国', 'China': '中国', 'Japan': '日本',
                        'Singapore': '新加坡', 'South Korea': '韩国', 'United Kingdom': '英国',
                        'France': '法国', 'Germany': '德国', 'Australia': '澳大利亚',
                        'Canada': '加拿大', 'Hong Kong': '中国香港', 'Taiwan': '中国台湾'
                    }
                    if country in eng_to_cn:
                        return eng_to_cn[country]
                    if len(country) == 2:
                        return COUNTRY_CODES.get(country, country)
                    return country
        except Exception:
            pass

        # 备用 ip-api.com
        try:
            url = f"http://ip-api.com/json/{ip}?fields=countryCode"
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success' and 'countryCode' in data:
                    return COUNTRY_CODES.get(data['countryCode'], data['countryCode'])
        except Exception:
            pass

        # 简单硬编码 Cloudflare 常见段
        octets = ip.split('.')
        if len(octets) >= 2 and octets[0] in ('104','108','162','172') and octets[1] in ('18','162','159','64'):
            return '美国'
        return '未知'
    except Exception:
        return '未知'

def clean_ip(ip_str):
    """验证并清理 IPv4 地址"""
    ip_str = ip_str.strip().rstrip(':')
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(pattern, ip_str):
        parts = ip_str.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return ip_str
    return None

# ==================== 测试核心类 ====================
class CloudflareNodeTester:
    def __init__(self):
        self.nodes = set()          # 所有待测 IP
        self.latency_results = []   # 延迟测试结果列表 [{ip, latency_ms, reachable}]
        self.detailed_results = []  # 详细测试结果 [{ip, latency, loss, speed, score}]
        self.lock = threading.Lock()

    # ------------------- 节点收集 -------------------
    def fetch_known_nodes(self):
        """生成一批 Cloudflare 常见 IP 段中的代表性 IP"""
        ip_ranges = [
            '104.24.0.0/16', '103.21.244.0/22', '103.31.4.0/22',
            '45.64.64.0/22', '104.28.0.0/16', '188.114.96.0/24',
            '188.114.97.0/24', '104.22.0.0/16', '104.25.0.0/16'
        ]
        for ip_range in ip_ranges:
            base_ip, cidr = ip_range.split('/')
            octets = base_ip.split('.')
            # 每个网段取前 20 个 IP（避免过多）
            for i in range(1, 21):
                ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{i + int(octets[3])}"
                self.nodes.add(ip)
        print(f"已加载 {len(self.nodes)} 个候选 IP")

    # ------------------- 1. TCP 延迟测试 -------------------
    def test_latency(self, ip):
        """测试 TCP 连接延迟，返回毫秒数，失败返回 None"""
        try:
            start = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TEST_TIMEOUT)
                if s.connect_ex((ip, TEST_PORT)) == 0:
                    return int((time.time() - start) * 1000)
            return None
        except Exception:
            return None

    def latency_worker(self, queue):
        """延迟测试线程工作函数"""
        while not queue.empty():
            ip = queue.get()
            latency = self.test_latency(ip)
            with self.lock:
                self.latency_results.append({
                    'ip': ip,
                    'latency_ms': latency,
                    'reachable': latency is not None
                })
                if len(self.latency_results) % 100 == 0:
                    print(f"延迟测试进度: {len(self.latency_results)}/{len(self.nodes)}")
            queue.task_done()

    def test_all_latency(self):
        """多线程测试所有节点的 TCP 延迟"""
        queue = Queue()
        for ip in self.nodes:
            queue.put(ip)
        threads = []
        thread_count = min(MAX_THREADS, len(self.nodes))
        for _ in range(thread_count):
            t = threading.Thread(target=self.latency_worker, args=(queue,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        print(f"延迟测试完成，有效节点: {sum(1 for r in self.latency_results if r['reachable'])}")

    # ------------------- 2. 丢包率测试 (ping) -------------------
    def test_loss(self, ip):
        """通过系统 ping 测试丢包率，返回丢包百分比 (0-100)"""
        if not ENABLE_LOSS_TEST:
            return 0.0
        try:
            # Linux ping 命令
            cmd = ['ping', '-c', str(PING_COUNT), '-W', str(PING_TIMEOUT), ip]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                             universal_newlines=True, timeout=10)
            # 解析丢包率，例: "5 packets transmitted, 5 received, 0% packet loss"
            match = re.search(r'(\d+)% packet loss', output)
            if match:
                return float(match.group(1))
            return 100.0
        except subprocess.CalledProcessError:
            return 100.0
        except Exception:
            return 100.0

    # ------------------- 3. 下载速度测试 -------------------
    def test_download_speed(self, ip):
        """通过 HTTP GET 下载测试文件，返回速度 (Mbps)，失败返回 0"""
        if not ENABLE_SPEED_TEST:
            return 0.0
        try:
            # 使用 requests 直接访问，但需要将 Host 头指向 speed.cloudflare.com
            # 为了避免 SSL 证书域名不匹配，这里加上 verify=False 并捕获异常
            headers = {'Host': 'speed.cloudflare.com'}
            start = time.time()
            resp = requests.get(SPEED_TEST_URL, headers=headers, timeout=SPEED_TEST_TIMEOUT,
                                verify=False)  # 忽略证书域名警告
            if resp.status_code == 200:
                elapsed = time.time() - start
                data_len = len(resp.content)   # 实际下载字节数
                speed_mbps = (data_len * 8) / (elapsed * 1_000_000)
                return round(speed_mbps, 2)
            return 0.0
        except Exception as e:
            # 静默失败，速度设为 0
            return 0.0

    # ------------------- 综合评分 -------------------
    def calculate_score(self, latency_ms, loss_percent, speed_mbps):
        """
        归一化后加权计算综合得分 (0-100 分)
        延迟: 假设 0ms 得 100 分，200ms 得 0 分
        丢包率: 0% 得 100 分，100% 得 0 分
        速度: 0 Mbps 得 0 分，50 Mbps 得 100 分 (超过满分)
        """
        latency_score = max(0, min(100, 100 - (latency_ms / 2))) if latency_ms else 0
        loss_score = 100 - loss_percent
        speed_score = min(100, (speed_mbps / 50) * 100)
        total = (latency_score * WEIGHT_LATENCY +
                 loss_score * WEIGHT_LOSS +
                 speed_score * WEIGHT_SPEED)
        return round(total, 2)

    # ------------------- 详细测试 (仅对候选节点) -------------------
    def detailed_test(self, candidates):
        """
        对候选节点列表 (ip 列表) 依次进行丢包和速度测试
        返回详细结果列表，按综合得分降序排序
        """
        print(f"\n开始对 {len(candidates)} 个候选节点进行丢包和速度测试...")
        detailed = []
        for idx, ip in enumerate(candidates, 1):
            # 找到该 IP 对应的延迟
            latency_info = next((r for r in self.latency_results if r['ip'] == ip), None)
            latency = latency_info['latency_ms'] if latency_info and latency_info['reachable'] else 9999
            loss = self.test_loss(ip) if ENABLE_LOSS_TEST else 0.0
            speed = self.test_download_speed(ip) if ENABLE_SPEED_TEST else 0.0
            score = self.calculate_score(latency, loss, speed)
            detailed.append({
                'ip': ip,
                'latency_ms': latency,
                'loss_percent': loss,
                'speed_mbps': speed,
                'score': score
            })
            print(f"  测试 {idx}/{len(candidates)}: {ip} 延迟={latency}ms 丢包={loss}% 速度={speed}Mbps 评分={score}")
        # 按综合得分降序排序
        detailed.sort(key=lambda x: x['score'], reverse=True)
        return detailed

    # ------------------- 主流程 -------------------
    def run(self):
        start_time = time.time()

        # 1. 获取节点列表
        self.fetch_known_nodes()
        if not self.nodes:
            print("未找到任何节点，退出")
            return

        # 2. 延迟测试 (所有节点)
        print("\n===== 第1阶段: TCP 延迟测试 =====")
        self.test_all_latency()

        # 3. 筛选候选节点 (延迟最低的前 CANDIDATE_COUNT 个)
        reachable = [r for r in self.latency_results if r['reachable']]
        if not reachable:
            print("没有可达节点，退出")
            return
        reachable.sort(key=lambda x: x['latency_ms'])
        candidate_ips = [r['ip'] for r in reachable[:CANDIDATE_COUNT]]
        print(f"已筛选出 {len(candidate_ips)} 个延迟最低的节点进行详细测试")

        # 4. 详细测试 (丢包 + 速度)
        print("\n===== 第2阶段: 丢包率 & 下载速度测试 =====")
        detailed_results = self.detailed_test(candidate_ips)

        # 5. 输出最终结果 (前 TOP_NODES 个)
        print("\n===== 最终排名 (IP#国家) =====")
        with open(TXT_OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for i, node in enumerate(detailed_results[:TOP_NODES], 1):
                country = get_ip_country(node['ip'])
                line = f"{node['ip']}#{country}"
                print(line)
                f.write(line + '\n')

        elapsed = int(time.time() - start_time)
        print(f"\n全部测试完成，耗时 {elapsed} 秒，结果已保存至 {TXT_OUTPUT_FILE}")

# ==================== 主入口 ====================
if __name__ == "__main__":
    try:
        # 禁用 requests 的 SSL 警告 (因为测试时用了 verify=False)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        tester = CloudflareNodeTester()
        tester.run()
    except KeyboardInterrupt:
        print("\n用户中断了程序")
    except Exception as e:
        print(f"程序出错: {e}")