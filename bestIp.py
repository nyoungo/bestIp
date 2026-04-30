import sys
import socket
import re
import time
import threading
import subprocess
import traceback
from queue import Queue
from datetime import datetime
import requests
import urllib3

# ==================== 配置参数 ====================
TEST_TIMEOUT = 3
TEST_PORT = 443
MAX_THREADS = 5
TOP_NODES_PER_COUNTRY = 2   # 每个国家取最快2个

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

# 用户提供的 IP 段（按国家分组）
# 每个项: (国家名称, [IP段列表])
COUNTRY_NETS = [
    ("日本", ["108.162.198.0/22"]),
    ("德国", [
        "104.21.0.0/24", "104.24.0.0/24", "104.25.0.0/24",
        "104.27.0.0/24", "104.26.0.0/24"
    ]),
    ("新加坡", [
        "108.162.192.0/24", "162.159.0.0/24", "172.64.32.0/24"
    ]),
    ("美国", [
        "104.16.0.0/22", "104.18.0.0/22", "104.19.0.0/22",
        "104.17.0.0/22", "103.31.4.0/22", "103.21.244.0/22"
    ])
]

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
        print(msg, file=sys.stderr)

# 初始化日志文件
try:
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write("")
    log("========== 脚本启动 ==========")
except Exception:
    pass

# ==================== 辅助函数 ====================
def cidr_to_ips(cidr, max_ips=20):
    """
    将 CIDR 网段转换为 IP 列表，每个网段最多生成 max_ips 个 IP
    支持 /22 和 /24
    """
    network, prefix = cidr.split('/')
    prefix = int(prefix)
    octets = list(map(int, network.split('.')))
    if prefix == 24:
        base = f"{octets[0]}.{octets[1]}.{octets[2]}"
        return [f"{base}.{i}" for i in range(1, min(max_ips, 254)+1)]
    elif prefix == 22:
        third_base = octets[2] & 0xFC  # 抹掉低2位
        ips = []
        for i in range(1, min(max_ips, 254)+1):
            ip = f"{octets[0]}.{octets[1]}.{third_base}.{i}"
            ips.append(ip)
        return ips
    else:
        log(f"不支持的掩码: {prefix}")
        return []

# ==================== 测试核心类 ====================
class CloudflareNodeTester:
    def __init__(self):
        self.country_nodes = {}
        self.lock = threading.Lock()
        self.ping_available = True
        self.speed_available = True

    def fetch_known_nodes(self):
        for country, nets in COUNTRY_NETS:
            ips = set()
            for net in nets:
                generated = cidr_to_ips(net, max_ips=20)
                ips.update(generated)
            self.country_nodes[country] = ips
            log(f"{country} 加载 {len(ips)} 个候选 IP")

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

    def latency_worker(self, queue, results_list):
        while not queue.empty():
            ip = queue.get()
            latency = self.test_latency(ip)
            with self.lock:
                results_list.append({
                    'ip': ip,
                    'latency_ms': latency,
                    'reachable': latency is not None
                })
            queue.task_done()

    def test_country_latency(self, country, ips):
        log(f"开始测试 {country} 的 {len(ips)} 个 IP 延迟...")
        queue = Queue()
        for ip in ips:
            queue.put(ip)
        results = []
        threads = []
        thread_count = min(MAX_THREADS, len(ips))
        for _ in range(thread_count):
            t = threading.Thread(target=self.latency_worker, args=(queue, results))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        reachable = sum(1 for r in results if r['reachable'])
        log(f"{country} 延迟测试完成，有效节点: {reachable}")
        return results

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
        except Exception:
            return 100.0

    def test_download_speed(self, ip):
        if not ENABLE_SPEED_TEST or not self.speed_available:
            return 0.0
        speed = self._do_speed_test(ip, 'https')
        if speed > 0:
            return speed
        return self._do_speed_test(ip, 'http')

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

    def detailed_test_for_country(self, country, latency_results, candidate_ips):
        log(f"开始对 {country} 的 {len(candidate_ips)} 个候选节点进行丢包和速度测试...")
        test_sample = candidate_ips[:3]
        ping_success = sum(1 for ip in test_sample if self.test_loss(ip) < 100)
        if ping_success == 0:
            self.ping_available = False
            log(f"{country}: ping 不可用，禁用丢包测试权重")
        speed_success = sum(1 for ip in test_sample if self.test_download_speed(ip) > 0)
        if speed_success == 0:
            self.speed_available = False
            log(f"{country}: 速度测试不可用，禁用速度测试权重")

        detailed = []
        for idx, ip in enumerate(candidate_ips, 1):
            latency_info = next((r for r in latency_results if r['ip'] == ip), None)
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
            log(f"{country} 测试 {idx}/{len(candidate_ips)}: {ip} 延迟={latency}ms 丢包={loss}% 速度={speed}Mbps 评分={score}")
        detailed.sort(key=lambda x: x['score'], reverse=True)
        return detailed

    def run(self):
        start_time = time.time()
        try:
            self.fetch_known_nodes()
            if not self.country_nodes:
                log("未加载任何节点，退出")
                return

            all_results = {}
            for country, ips in self.country_nodes.items():
                log(f"\n===== 开始测试国家: {country} =====")
                latency_results = self.test_country_latency(country, ips)
                reachable = [r for r in latency_results if r['reachable']]
                if not reachable:
                    log(f"{country} 没有可达节点，跳过")
                    continue
                reachable.sort(key=lambda x: x['latency_ms'])
                candidate_ips = [r['ip'] for r in reachable[:30]]
                log(f"{country} 筛选出 {len(candidate_ips)} 个延迟最低的节点")
                detailed_results = self.detailed_test_for_country(country, latency_results, candidate_ips)
                all_results[country] = detailed_results[:TOP_NODES_PER_COUNTRY]

            with open(TXT_OUTPUT_FILE, 'w', encoding='utf-8') as f:
                for country, nodes in all_results.items():
                    for node in nodes:
                        line = f"{node['ip']}#{country}"
                        f.write(line + '\n')
                        log(line)

            elapsed = int(time.time() - start_time)
            log(f"\n全部测试完成，耗时 {elapsed} 秒，结果已保存至 {TXT_OUTPUT_FILE}")
        except Exception as e:
            log(f"运行过程中发生未捕获异常: {e}\n{traceback.format_exc()}")

if __name__ == "__main__":
    try:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        tester = CloudflareNodeTester()
        tester.run()
    except KeyboardInterrupt:
        log("\n用户中断了程序")
    except Exception as e:
        log(f"顶级异常: {e}\n{traceback.format_exc()}")