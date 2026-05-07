#!/usr/bin/env python3
import re
import sys
import requests
import argparse
from pathlib import Path

def fetch_content(url: str) -> str:
    try:
        response = requests.get(url, timeout=30)
        response.encoding = 'utf-8'
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {e}", file=sys.stderr)
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
    parser = argparse.ArgumentParser(description='Process IP list.')
    parser.add_argument('-u', '--url',
                        default='https://raw.githubusercontent.com/HandsomeMJZ/cfip/refs/heads/main/best_ips.txt',
                        help='URL to fetch data from')
    parser.add_argument('-o', '--output', default='ip.txt',
                        help='Output file name')
    args = parser.parse_args()
    content = fetch_content(args.url)
    processed = process_content(content)
    save_output(processed, args.output)
    print(f"Processed {len(processed)} entries and saved to {args.output}")

if __name__ == "__main__":
    main()