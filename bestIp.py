import socket
import re
import time
import threading
import subprocess
import traceback
from queue import Queue
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# ==================== 配置参数 ====================
TEST_TIMEOUT = 3
TEST_PORT = 443
MAX_THREADS = 5
CANDIDATE_COUNT = 30
TOP_NODES = 9

ENABLE_LOSS_TEST = True
PING_COUNT = 4
PING_TIMEOUT = 2

ENABLE_SPEED_TEST = True
SPEED_TEST_PATH = "/__down?bytes=10485760"
SPEED_TEST_HOST = "speed.cloudflare.com"
SPEED_TEST_TIMEOUT = 15

WEIGHT_LATENCY = 0.4
WEIGHT_LOSS = 0.3
WEIGHT_SPEED = 0.3

TXT_OUTPUT_FILE = "bestIp.txt"
LOG_FILE = "log.txt"

COUNTRY_CODES = {
    'US': '美国', 'CN': '中国', 'JP': '日本', 'SG': '新加坡', 'KR': '韩国',
    'GB': '英国', 'FR': '法国', 'DE': '德国', 'AU': '澳大利亚', 'CA': '加拿大',
    'HK': '中国香港', 'TW': '中国台湾', 'IN': '印度', 'RU': '俄罗斯',
    'BR': '巴西', 'MX': '墨西哥', 'NL': '荷兰', 'SE': '瑞典', 'CH': '瑞士',
    'IT': '意大利', 'ES': '西班牙', 'Unknown': '未知'
}

log_lock = threading.Lock()

def log(msg, also_print=True):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with log_lock:
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"[{timestamp}] {msg}\n")
        except Exception:
            pass
    if also_print:
        print(msg)

# 初始化日志（清空旧内容）
try:
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write("")
    log("========== 脚本启动 ==========")
except Exception:
    pass

# ==================== 辅助函数 ====================
def get_ip_country(ip):
    try:
        socket.inet_aton(ip)
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500,502,503,504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        try:
            url = f"https://ipwhois.app/json/{ip}"
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if 'country' in data and data['country']:
                    country = data['country']
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

        try:
            url = f"http://ip-api.com/json/{ip}?fields=countryCode"
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success' and 'countryCode' in data:
                    return COUNTRY_CODES.get(data['countryCode'], data['countryCode'])
        except Exception:
            pass

        octets = ip.split('.')
        if len(octets) >= 2 and octets[0] in ('104','108','162','172') and octets[1] in ('18','162','159','64'):
            return '美国'
        return '未知'
    except Exception as e:
        log(f"IP 国家查询失败 {ip}: {e}")
        return '未知'

# ==================== 测试核心类 ====================
class CloudflareNodeTester:
    def __init__(self):
        self.nodes = set()
        self.latency_results = []
        self.detailed_results = []
        self.lock = threading.Lock()
        self.ping_available = True
        self.speed_available = True

    def fetch_known_nodes(self):
        ip_ranges = [
            '104.24.0.0/16', '103.21.244.0/22', '103.31.4.0/22',
            '45.64.64.0/22', '104.28.0.0/16', '188.114.96.0/24',
            '188.114.97.0/24', '104.22.0.0/16', '104.25.0.0/16'
        ]
        for ip_range in ip_ranges:
            base_ip, cidr = ip_range.split('/')
            octets = base_ip.split('.')
            for i in range(1, 21):
                ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{i + int(octets[3])}"
                self.nodes.add(ip)
        log(f"已加载 {len(self.nodes)} 个候选 IP")

    def test_latency(self, ip):
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
                    log(f"延迟测试进度: {len(self.latency_results)}/{len(self.nodes)}")
            queue.task_done()

    def test_all_latency(self):
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
        reachable = sum(1 for r in self.latency_results if r['reachable'])
        log(f"延迟测试完成，有效节点: {reachable}")

    def test_loss(self, ip):
        if not ENABLE_LOSS_TEST or not self.ping_available:
            return 0.0
        try:
            cmd = ['ping', '-c', str(PING_COUNT), '-W', str(PING_TIMEOUT), ip]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                             universal_newlines=True, timeout=10)
            match = re.search(r'(\d+)% packet loss', output)
            if match:
                return float(match.group(1))
            return 100.0
        except subprocess.CalledProcessError:
            return 100.0
        except Exception:
            return 100.0

    def test_download_speed(self, ip):
        if not ENABLE_SPEED_TEST or not self.speed_available:
            return 0.0
        speed = self._do_speed_test(ip, 'https')
        if speed > 0:
            return speed
        speed = self._do_speed_test(ip, 'http')
        return speed

    def _do_speed_test(self, ip, scheme):
        url = f"{scheme}://{ip}{SPEED_TEST_PATH}"
        headers = {'Host': SPEED_TEST_HOST}
        try:
            start = time.time()
            resp = requests.get(url, headers=headers, timeout=SPEED_TEST_TIMEOUT,
                                stream=True, verify=False)
            total_bytes = 0
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    total_bytes += len(chunk)
            elapsed = time.time() - start
            if elapsed > 0 and total_bytes > 0:
                speed_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
                return round(speed_mbps, 2)
            return 0.0
        except Exception:
            return 0.0

    def calculate_score(self, latency_ms, loss_percent, speed_mbps):
        latency_score = max(0, min(100, 100 - (latency_ms / 2))) if latency_ms else 0
        loss_score = 100 - loss_percent
        speed_score = min(100, (speed_mbps / 20) * 100) if speed_mbps else 0
        w_lat = WEIGHT_LATENCY
        w_loss = WEIGHT_LOSS if self.ping_available else 0
        w_spd = WEIGHT_SPEED if self.speed_available else 0
        total_weight = w_lat + w_loss + w_spd
        if total_weight == 0:
            return latency_score
        total = (latency_score * w_lat + loss_score * w_loss + speed_score * w_spd) / total_weight
        return round(total, 2)

    def detailed_test(self, candidates):
        log(f"\n开始对 {len(candidates)} 个候选节点进行丢包和速度测试...")
        # 检测可用性
        test_sample = candidates[:3]
        ping_success = sum(1 for ip in test_sample if self.test_loss(ip) < 100)
        if ping_success == 0:
            self.ping_available = False
            log("检测到 ping 不可用，禁用丢包测试权重")
        speed_success = sum(1 for ip in test_sample if self.test_download_speed(ip) > 0)
        if speed_success == 0:
            self.speed_available = False
            log("检测到速度测试不可用，禁用速度测试权重")

        detailed = []
        for idx, ip in enumerate(candidates, 1):
            latency_info = next((r for r in self.latency_results if r['ip'] == ip), None)
            latency = latency_info['latency_ms'] if latency_info and latency_info['reachable'] else 9999
            loss = self.test_loss(ip) if self.ping_available else 0.0
            speed = self.test_download_speed(ip) if self.speed_available else 0.0
            score = self.calculate_score(latency, loss, speed)
            detailed.append({
                'ip': ip,
                'latency_ms': latency,
                'loss_percent': loss,
                'speed_mbps': speed,
                'score': score
            })
            log(f"  测试 {idx}/{len(candidates)}: {ip} 延迟={latency}ms 丢包={loss}% 速度={speed}Mbps 评分={score}")
        detailed.sort(key=lambda x: x['score'], reverse=True)
        return detailed

    def run(self):
        start_time = time.time()
        try:
            self.fetch_known_nodes()
            if not self.nodes:
                log("未找到任何节点，退出")
                # bestIp.txt 保持为空（不写入任何内容）
                return

            log("\n===== 第1阶段: TCP 延迟测试 =====")
            self.test_all_latency()

            reachable = [r for r in self.latency_results if r['reachable']]
            if not reachable:
                log("警告：没有可达节点，不生成 bestIp.txt（空文件）")
                return

            reachable.sort(key=lambda x: x['latency_ms'])
            candidate_ips = [r['ip'] for r in reachable[:CANDIDATE_COUNT]]
            log(f"已筛选出 {len(candidate_ips)} 个延迟最低的节点进行详细测试")

            log("\n===== 第2阶段: 丢包率 & 下载速度测试 =====")
            detailed_results = self.detailed_test(candidate_ips)

            log("\n===== 最终排名 (IP#国家) =====")
            with open(TXT_OUTPUT_FILE, 'w', encoding='utf-8') as f:
                for node in detailed_results[:TOP_NODES]:
                    country = get_ip_country(node['ip'])
                    line = f"{node['ip']}#{country}\n"
                    f.write(line)
                    log(line.rstrip())

            elapsed = int(time.time() - start_time)
            log(f"\n全部测试完成，耗时 {elapsed} 秒，结果已保存至 {TXT_OUTPUT_FILE}")

        except Exception as e:
            log(f"运行过程中发生未捕获异常: {e}\n{traceback.format_exc()}")
            # 异常时也不写入 bestIp.txt 的注释，保持为空或旧内容不变
            # 这里为了安全，不写入任何内容

# ==================== 主入口 ====================
if __name__ == "__main__":
    try:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        tester = CloudflareNodeTester()
        tester.run()
    except KeyboardInterrupt:
        log("\n用户中断了程序")
    except Exception as e:
        log(f"顶级异常: {e}\n{traceback.format_exc()}")
        # 不写入 bestIp.txt