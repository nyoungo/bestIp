import sys
import socket
import re
import time
import threading
import subprocess
import traceback
import random
from queue import Queue
from datetime import datetime
import requests
import urllib3
import ipaddress
from collections import defaultdict

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

# Cloudflare IPv4 段在线地址
CIDR_LIST_URL = "https://bestcf.pages.dev/CIDR/all.txt"

# GeoIP 查询配置
GEOIP_API = "http://ip-api.com/json/{}?fields=country"
GEOIP_TIMEOUT = 5
GEOIP_INTERVAL = 0.8          # 每个查询间隔（秒），避免超限
MAX_RETRY_GEOIP = 2           # 查询失败重试次数

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
    从 CIDR 网段中随机抽取最多 max_ips 个有效主机 IP
    """
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        # 收集所有可用主机地址
        if net.prefixlen == 32:
            hosts = [net.network_address]
        elif net.prefixlen == 31:
            hosts = list(net.hosts())
        else:
            hosts = list(net.hosts())

        if not hosts:
            return []

        # 随机抽取，最多 max_ips 个
        sample_size = min(max_ips, len(hosts))
        sampled_ips = random.sample(hosts, sample_size)
        return [str(ip) for ip in sampled_ips]
    except Exception as e:
        log(f"无法解析 CIDR {cidr}: {e}")
        return []

def fetch_cidr_list(url):
    """从在线 URL 获取 IPv4 CIDR 列表"""
    try:
        log(f"正在从 {url} 下载 Cloudflare IPv4 范围...")
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        lines = resp.text.strip().splitlines()
        cidrs = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # 简单验证是否为有效 CIDR
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', line):
                cidrs.append(line)
        log(f"成功获取 {len(cidrs)} 个 IPv4 CIDR")
        return list(set(cidrs))  # 去重
    except Exception as e:
        log(f"获取 CIDR 列表失败: {e}")
        sys.exit(1)

def get_country_from_ip(ip):
    """通过 ip-api.com 查询单个 IP 所属国家"""
    url = GEOIP_API.format(ip)
    for attempt in range(MAX_RETRY_GEOIP + 1):
        try:
            resp = requests.get(url, timeout=GEOIP_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                return data.get('country', 'Unknown')
            else:
                log(f"GeoIP 查询返回状态码 {resp.status_code}，IP: {ip}", also_print=False)
        except Exception as e:
            log(f"GeoIP 查询异常 (尝试 {attempt+1}): {e}", also_print=False)
        if attempt < MAX_RETRY_GEOIP:
            time.sleep(1)
    return 'Unknown'

def build_country_nets(cidrs):
    """
    对每个 CIDR 取一个代表 IP，查询国家，构建 COUNTRY_NETS 结构
    返回: list of (country, [cidr_list])
    """
    country_dict = defaultdict(list)
    total = len(cidrs)
    log(f"开始对 {total} 个 CIDR 进行国家分类...")
    for idx, cidr in enumerate(cidrs, 1):
        try:
            # 取网络地址 +1 作为代表 IP
            net = ipaddress.IPv4Network(cidr, strict=False)
            if net.num_addresses >= 2:
                rep_ip = str(net.network_address + 1)
            else:
                rep_ip = str(net.network_address)   # /32 的情况
        except Exception as e:
            log(f"解析 CIDR {cidr} 失败: {e}，跳过")
            continue

        country = get_country_from_ip(rep_ip)
        country_dict[country].append(cidr)
        log(f"[{idx}/{total}] {cidr} -> {rep_ip} -> {country}")

        # 限速，避免请求过快
        time.sleep(GEOIP_INTERVAL)

    # 转换为历史使用的列表格式
    result = list(country_dict.items())
    result.sort(key=lambda x: x[0])  # 按国家名排序，便于阅读
    log(f"国家分类完成，共 {len(result)} 个国家/地区：")
    for country, nets in result:
        log(f"  {country}: {len(nets)} 个 CIDR")
    return result

# ==================== 测试核心类 ====================
class CloudflareNodeTester:
    def __init__(self):
        self.country_nodes = {}
        self.lock = threading.Lock()
        self.ping_available = True
        self.speed_available = True
        self.country_nets = []  # 将在运行时动态生成

    def fetch_known_nodes(self):
        """加载网段并预检首IP，只保留可达网段，从中随机抽取IP"""
        for country, nets in self.country_nets:
            ips = set()
            for net in nets:
                # 获取该网段的第一个可用 IP（网络地址+1 或网络地址）
                try:
                    net_obj = ipaddress.IPv4Network(net, strict=False)
                    first_ip = str(net_obj.network_address + 1) if net_obj.num_addresses >= 2 else str(net_obj.network_address)
                except Exception as e:
                    log(f"解析 CIDR {net} 失败: {e}，跳过")
                    continue

                # 预检测：如果第一个 IP 不通，跳过整个网段
                if self.test_latency(first_ip) is None:
                    log(f"跳过不可达网段: {net} (首IP {first_ip} 不通)")
                    continue

                # 首IP连通，随机抽取网段内的最多20个IP
                generated = cidr_to_ips(net, max_ips=20)
                ips.update(generated)
                log(f"网段 {net} 首IP可达，随机抽取 {len(generated)} 个 IP 加入测试", also_print=False)

            if ips:
                self.country_nodes[country] = ips
                log(f"{country} 加载 {len(ips)} 个候选 IP")
            else:
                log(f"{country} 没有可用网段，跳过")

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
            # ---------- 动态获取 CIDR 并生成 COUNTRY_NETS ----------
            cidr_list = fetch_cidr_list(CIDR_LIST_URL)
            self.country_nets = build_country_nets(cidr_list)
            if not self.country_nets:
                log("未生成任何国家-IP段映射，退出")
                return

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
