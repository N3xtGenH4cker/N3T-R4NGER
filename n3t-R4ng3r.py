#!/usr/bin/env python3
"""
Managed Network Scanner for Penetration Testing
Efficiently scans large network ranges with proper resource management
"""

import argparse
import subprocess
import sys
import threading
import time
import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
import re

def script_banner():
    print(r"""
 _        ______ _________     _______     ___    _        _______  ______   _______ 
( (    /|/ ___  \\__   __/    (  ____ )   /   )  ( (    /|(  ____ \/ ___  \ (  ____ )
|  \  ( |\/   \  \  ) (       | (    )|  / /) |  |  \  ( || (    \/\/   \  \| (    )|
|   \ | |   ___) /  | | _____ | (____)| / (_) (_ |   \ | || |         ___) /| (____)|
| (\ \) |  (___ (   | |(_____)|     __)(____   _)| (\ \) || | ____   (___ ( |     __)
| | \   |      ) \  | |       | (\ (        ) (  | | \   || | \_  )      ) \| (\ (   
| )  \  |/\___/  /  | |       | ) \ \__     | |  | )  \  || (___) |/\___/  /| ) \ \__
|/    )_)\______/   )_(       |/   \__/     (_)  |/    )_)(_______)\______/ |/   \__/
                                                                                                                                                                         
""")

class NetworkScanner:
    def __init__(self, target_range, max_threads=50, delay=0.1):
        self.target_range = target_range
        self.max_threads = max_threads
        self.delay = delay
        self.results_queue = Queue()
        self.active_scans = 0
        self.completed_scans = 0
        self.total_hosts = 0
        self.lock = threading.Lock()
        
        try:
            self.network = ipaddress.IPv4Network(target_range, strict=False)
            self.total_hosts = self.network.num_addresses
            if self.total_hosts > 65536:  # /16 is 65536 hosts
                print(f"Warning: Large range detected ({self.total_hosts} hosts)")
        except ValueError as e:
            print(f"Error: Invalid network range - {e}")
            sys.exit(1)
            
        range_clean = target_range.replace('/', '_').replace('.', '-')
        self.output_base = f"{range_clean}-network"
        
    def check_nmap_installed(self):
        """Check if nmap is installed and accessible"""
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("Error: nmap is not installed or not in PATH")
            return False
    
    def ping_sweep(self):
        """Perform initial ping sweep to identify live hosts"""
        print(f"[*] Starting ping sweep on {self.target_range}")
        print(f"[*] Scanning {self.total_hosts} potential hosts...")
        
        cmd = [
            'nmap', '-sn', '-T4', '--max-retries', '1',
            '--host-timeout', '3s', str(self.target_range)
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            live_hosts = []
            
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        live_hosts.append(ip_match.group(1))
            
            print(f"[+] Found {len(live_hosts)} live hosts")
            return live_hosts
            
        except subprocess.TimeoutExpired:
            print("[-] Ping sweep timed out, proceeding with full range scan")
            return [str(ip) for ip in self.network.hosts()]
        except Exception as e:
            print(f"[-] Ping sweep failed: {e}")
            return [str(ip) for ip in self.network.hosts()]
    
    def scan_host(self, host_ip):
        """Perform detailed scan on a single host"""
        with self.lock:
            self.active_scans += 1
            
        try:
            cmd = [
                'nmap', '-sS', '-sC', '-sV', '-T4',
                '--max-retries', '2',
                '--host-timeout', '10m',
                '-p-', 
                host_ip
            ]
            
            print(f"[*] Scanning {host_ip} ({self.completed_scans + 1}/{len(self.live_hosts)})")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            
            if result.returncode == 0 and 'open' in result.stdout.lower():
                self.process_scan_result(host_ip, result.stdout)
                
            time.sleep(self.delay)
            
        except subprocess.TimeoutExpired:
            print(f"[-] Scan timeout for {host_ip}")
        except Exception as e:
            print(f"[-] Error scanning {host_ip}: {e}")
        finally:
            with self.lock:
                self.active_scans -= 1
                self.completed_scans += 1
    
    def process_scan_result(self, host_ip, nmap_output):
        """Process and display scan results in real-time"""
        print(f"\n{'='*60}")
        print(f"[+] RESULTS for {host_ip}")
        print(f"{'='*60}")

        in_port_section = False
        open_ports = []
        
        for line in nmap_output.split('\n'):
            if 'PORT' in line and 'STATE' in line:
                in_port_section = True
                print(line)
                continue
            elif in_port_section and line.strip():
                if '/tcp' in line or '/udp' in line:
                    print(line)
                    parts = line.split()
                    if len(parts) >= 3 and 'open' in parts[1]:
                        open_ports.append(parts[0])
                elif line.startswith('|'):
                    print(line)
                else:
                    in_port_section = False
        
        if open_ports:
            print(f"\n[+] {host_ip} - Open ports: {', '.join(open_ports)}")
        
        self.results_queue.put((host_ip, nmap_output))
        print(f"{'='*60}\n")
    
    def save_results(self):
        """Save all results to output files"""
        print(f"[*] Saving results to {self.output_base}.*")
        
        all_results = []
        while not self.results_queue.empty():
            all_results.append(self.results_queue.get())
        
        if not all_results:
            print("[-] No results to save")
            return
        
        try:
            with open(f"{self.output_base}.xml", 'w') as f:
                f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                f.write('<nmaprun>\n')
                for host_ip, output in all_results:
                    f.write(f'  <host ip="{host_ip}">\n')
                    f.write(f'    <output><![CDATA[{output}]]></output>\n')
                    f.write('  </host>\n')
                f.write('</nmaprun>\n')
            
            # Normal text format
            with open(f"{self.output_base}.nmap", 'w') as f:
                f.write(f"# Network scan results for {self.target_range}\n")
                f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for host_ip, output in all_results:
                    f.write(f"{'='*60}\n")
                    f.write(f"Host: {host_ip}\n")
                    f.write(f"{'='*60}\n")
                    f.write(output)
                    f.write("\n\n")
            
            with open(f"{self.output_base}.gnmap", 'w') as f:
                for host_ip, output in all_results:
                    ports = []
                    for line in output.split('\n'):
                        if '/tcp' in line and 'open' in line:
                            port_match = re.match(r'(\d+/tcp)', line)
                            if port_match:
                                ports.append(port_match.group(1))
                    
                    if ports:
                        f.write(f"Host: {host_ip} () Status: Up\n")
                        f.write(f"Host: {host_ip} () Ports: {'/'.join(ports)}\n")
            
            print(f"[+] Results saved to {self.output_base}.{{xml,nmap,gnmap}}")
            
        except Exception as e:
            print(f"[-] Error saving results: {e}")
    
    def run_scan(self):
        """Main scanning function"""
        if not self.check_nmap_installed():
            return False
        
        print(f"[*] Starting managed network scan")
        print(f"[*] Target: {self.target_range}")
        print(f"[*] Max threads: {self.max_threads}")
        print(f"[*] Output: {self.output_base}.*")
        
        start_time = time.time()
        
        self.live_hosts = self.ping_sweep()
        
        if not self.live_hosts:
            print("[-] No live hosts found")
            return False
        
        print(f"[*] Starting detailed scans on {len(self.live_hosts)} hosts")
        print(f"[*] Using {min(self.max_threads, len(self.live_hosts))} concurrent threads")
        
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(self.live_hosts))) as executor:
            futures = {executor.submit(self.scan_host, host): host for host in self.live_hosts}
            
            for future in as_completed(futures):
                host = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Failed to scan {host}: {e}")
        
        self.save_results()
        
        elapsed_time = time.time() - start_time
        print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds")
        print(f"[+] Scanned {len(self.live_hosts)} live hosts")
        print(f"[+] Found results for {self.results_queue.qsize()} hosts")
        
        return True

def main():
    script_banner()
    parser = argparse.ArgumentParser(
        description="Managed Network Scanner for Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -r 192.168.1.0/24
  python3 scanner.py -r 10.0.0.0/16 --threads 30 --delay 0.2
        """
    )
    
    parser.add_argument('-r', '--range', required=True,
                       help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--threads', type=int, default=50,
                       help='Maximum concurrent threads (default: 50)')
    parser.add_argument('--delay', type=float, default=0.1,
                       help='Delay between scans in seconds (default: 0.1)')
    
    args = parser.parse_args()
    
    if args.threads < 1 or args.threads > 200:
        print("Error: Thread count must be between 1 and 200")
        sys.exit(1)
    
    scanner = NetworkScanner(args.range, args.threads, args.delay)
    
    try:
        success = scanner.run_scan()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        print("[*] Saving partial results...")
        scanner.save_results()
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
