#!/usr/bin/env python3
import re
import sys
import requests
from pathlib import Path

def fetch_content(url: str) -> str:
    try:
        response = requests.get(url, timeout=30)
        response.encoding = 'utf-8'
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL {url}: {e}", file=sys.stderr)
        sys.exit(1)

def process_line(line: str) -> list[str]:
    tokens = line.strip().split()
    results = []
    for token in tokens:
        base = token.split('[')[0].strip()
        if base and '#' in base:
            parts = base.split('#')
            ip_with_port = parts[0]
            country_code = parts[1] if len(parts) > 1 else ''
            ip = ip_with_port.split(':')[0]
            if ip and country_code:
                results.append(f"{ip}#{country_code}")
            elif ip:
                results.append(f"{ip}#Unknown")
    return results

def process_content(content: str) -> list[str]:
    lines = content.splitlines()
    parsed = set()
    for line in lines:
        if not line.strip():
            continue
        parsed.update(process_line(line))
    return sorted(parsed)

def save_output(data: list[str], output_file: str) -> None:
    output_path = Path(output_file)
    with output_path.open('w', encoding='utf-8') as f:
        f.write('\n'.join(data))
        if data:
            f.write('\n')

def main():
    tasks = [
        ("https://raw.githubusercontent.com/HandsomeMJZ/cfip/refs/heads/main/best_ips.txt", "liantong.txt"),
        ("https://raw.githubusercontent.com/svip-s/cloudflare_ip/refs/heads/main/best_ips.txt", "yidong.txt"),
        ("https://raw.githubusercontent.com/love-ztm/cfip/refs/heads/main/ubest_ips.txt", "dianxin.txt")
    ]

    for url, output_file in tasks:
        print(f"Processing {url} -> {output_file}")
        content = fetch_content(url)
        processed = process_content(content)
        save_output(processed, output_file)
        print(f"Processed {len(processed)} entries and saved to {output_file}")

if __name__ == "__main__":
    main()
