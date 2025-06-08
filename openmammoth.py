#!/usr/bin/env python3
import os
import sys
import json
import time
import threading
import logging
import ipaddress
import re
import hashlib
import socket
import subprocess
import requests
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import init, Fore, Style

# Initialize colorama
init()

class OpenMammoth:
    def __init__(self):
        self.protection_level = 2
        self.advanced_protection = False
        self.debug_mode = False
        self.interface = None
        self.blocked_ips = {}
        self.stats = {
            "total_packets": 0,
            "blocked_packets": 0,
            "attacks_detected": 0,
            "port_scans": 0,
            "syn_floods": 0,
            "udp_floods": 0,
            "icmp_floods": 0,
            "dns_amplification": 0,
            "fragment_attacks": 0,
            "malformed_packets": 0,
            "spoofed_ips": 0,
            "threat_intel_blocks": 0,
            "reputation_blocks": 0
        }
        self.connection_tracker = {}
        self.packet_rates = {}
        self.is_running = False
        self.capture_thread = None
        self.cleanup_thread = None
        self.update_thread = None
        self.last_cleanup_time = 0
        self.cleanup_interval = 300  # Clean up every 5 minutes
        self.config_dir = "/etc/securonis"
        self.threat_intel_db = {}
        self.ip_reputation_db = {}
        self.whitelist = []
        self.blacklist = []
        self.use_threat_intel = True
        self.auto_update = True
        self.last_update_check = 0
        self.update_interval = 86400  # 24 hours
        self.local_ips = []
        
        # Check system requirements
        self.check_system_requirements()
        
        if not os.path.exists(self.config_dir):
            try:
                os.makedirs(self.config_dir)
            except PermissionError:
                print(f"{Fore.RED}Error: Permission denied when creating {self.config_dir}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Please run the program with root privileges.{Style.RESET_ALL}")
                sys.exit(1)
            except Exception as e:
                print(f"{Fore.RED}Error creating config directory: {str(e)}{Style.RESET_ALL}")
                sys.exit(1)
                
        self.load_config()
        self.setup_logging()
        self.available_interfaces = self.get_available_interfaces()
        self.detect_local_ips()
        self.load_threat_intel()
        self.load_ip_lists()
        
        # Show warning if no interfaces found and wait for user to press Enter
        if not self.available_interfaces:
            os.system('clear')
            print(self.get_ascii_art())
            print(f"\n{Fore.RED}Warning: No network interfaces found!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}You can configure network interfaces from the main menu.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Option 8: Configure Network Interfaces{Style.RESET_ALL}")
            input("\nPress Enter to continue to main menu...")

    def get_ascii_art(self):
        return f"""{Fore.RED}
                                     .                                
                             #@- .=.*%*+:                             
                           @# #%%%%%#####**                           
                          .+ @@###*#*####*%-                          
                        =*@ @@#############%**:                       
                     .@@##@ +-@%###########**##%#:                    
                    %@%*#@# %@%##########*###%####=                   
                    @=%#%% @@@@########%@@%%*##*%#@                   
                   :@#%#%% @@ @@@@@@@@@%..@=*%#*@ @                   
                     .%##@# @@@#  -=. @%@@@+%#*#@                     
                     -*%%@@# @+.@@@@@@@##%##%%#%                      
                      .@ @#@ @ .  -:. +%#%%%#=#=                      
                @-     : @@# @ %@@@@@@@%%%.@@:    : *%                
              @*          :# @ . .--. @### %.         *%              
            -@.            *@@ #@@@@@@@##@%            -#=            
           *#@+           .@ @+.      @###@             %##           
           @#+           .@ -@@ @@@@@@@%###@            =#@           
           @#@+         +@ *@#@   ::. %#=%#*@:-         +#@           
           +##        .@  @@=:@ @@@@@@%%--%####         @*%           
            %##%#-=**-  @@@   %.  .. #%*.  *=##+*:  .:##%%            
             :#%+...=@@@+     -@ @@@@@%:     =#%%###%%%#:             
                :#%%:          @ %--=*@          .--:                 
                              -@ #%#@#@                               
                            -  # @@%**=                               
                            @: #.*.%#@:                               
                           +@  @ @@%#:                                
                           :*%@ #@#%+                                 
                            ##@@@%#                                   
{Style.RESET_ALL}"""

    def setup_logging(self):
        # Create /etc/securonis directory if it doesn't exist
        log_dir = "/etc/securonis"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        logging.basicConfig(
            filename=os.path.join(log_dir, 'openmammoth.log'),
            level=logging.DEBUG if self.debug_mode else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def load_config(self):
        try:
            config_path = os.path.join(self.config_dir, 'config.json')
            with open(config_path, 'r') as f:
                config = json.load(f)
                self.protection_level = config.get('protection_level', 2)
                self.advanced_protection = config.get('advanced_protection', False)
                self.debug_mode = config.get('debug_mode', False)
                self.interface = config.get('interface', None)
                self.use_threat_intel = config.get('use_threat_intel', True)
                self.auto_update = config.get('auto_update', True)
                self.whitelist = config.get('whitelist', [])
                self.blacklist = config.get('blacklist', [])
                self.update_interval = config.get('update_interval', 86400)
                self.last_update_check = config.get('last_update_check', 0)
        except FileNotFoundError:
            self.save_config()
        except json.JSONDecodeError:
            logging.error("Config file is corrupted. Loading defaults.")
            self.save_config()
        except Exception as e:
            logging.error(f"Error loading config: {str(e)}")
            self.save_config()

    def save_config(self):
        config = {
            'protection_level': self.protection_level,
            'advanced_protection': self.advanced_protection,
            'debug_mode': self.debug_mode,
            'interface': self.interface,
            'use_threat_intel': self.use_threat_intel,
            'auto_update': self.auto_update,
            'whitelist': self.whitelist,
            'blacklist': self.blacklist,
            'update_interval': self.update_interval,
            'last_update_check': self.last_update_check
        }
        try:
            config_path = os.path.join(self.config_dir, 'config.json')
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {str(e)}")

    def packet_handler(self, packet):
        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                
                # First check if it's in the whitelist
                if self.is_ip_in_whitelist(ip_src):
                    self.stats['total_packets'] += 1
                    return
                
                # Check if it's a local IP address
                if ip_src in self.local_ips:
                    self.stats['total_packets'] += 1
                    return
                
                # Perform IP reputation check
                if self.check_ip_reputation(ip_src):
                    self.block_ip(ip_src, reason="Reputation based block")
                    self.stats['blocked_packets'] += 1
                    print(f"{Fore.RED}[!] Blocked malicious IP: {ip_src} (Reputation){Style.RESET_ALL}")
                    logging.warning(f"IP blocked due to reputation: {ip_src}")
                    self.stats['total_packets'] += 1
                    return
                
                # Update connection tracking
                self.update_connection_tracker(ip_src, ip_dst)
                
                # Update packet rates
                self.update_packet_rates(ip_src)
                
                # Check for various types of attacks
                if self.detect_attacks(packet):
                    self.block_ip(ip_src, reason="Attack detected")
                    self.stats['blocked_packets'] += 1
                    self.stats['attacks_detected'] += 1
                    print(f"{Fore.RED}[!] Attack detected and blocked from: {ip_src}{Style.RESET_ALL}")
                    logging.warning(f"Attack detected from {ip_src}")
                
                self.stats['total_packets'] += 1
                
                # Log periodic statistics
                if self.stats['total_packets'] % 1000 == 0:  # Her 1000 pakette bir log
                    print(f"\n{Fore.CYAN}[*] Protection Statistics:{Style.RESET_ALL}")
                    print(f"Total Packets: {self.stats['total_packets']}")
                    print(f"Blocked Packets: {self.stats['blocked_packets']}")
                    print(f"Attacks Detected: {self.stats['attacks_detected']}\n")
                    
        except Exception as e:
            logging.error(f"Error in packet handler: {str(e)}")

    def update_connection_tracker(self, src_ip, dst_ip):
        key = f"{src_ip}-{dst_ip}"
        if key not in self.connection_tracker:
            self.connection_tracker[key] = {
                'count': 1,
                'timestamp': time.time()
            }
        else:
            self.connection_tracker[key]['count'] += 1

    def update_packet_rates(self, ip):
        current_time = time.time()
        if ip not in self.packet_rates:
            self.packet_rates[ip] = {
                'count': 1,
                'timestamp': current_time
            }
        else:
            if current_time - self.packet_rates[ip]['timestamp'] > 1:
                self.packet_rates[ip] = {
                    'count': 1,
                    'timestamp': current_time
                }
            else:
                self.packet_rates[ip]['count'] += 1

    def detect_attacks(self, packet):
        """Detect various types of attacks"""
        if IP in packet:
            ip_src = packet[IP].src
            
            # Skip local network traffic completely
            if self.is_local_network(ip_src) or ip_src in self.local_ips:
                return False
            
            # Skip whitelisted IPs
            if self.is_ip_in_whitelist(ip_src):
                return False
            
            # Skip router and gateway IPs
            if ip_src.endswith('.1') or ip_src.endswith('.254'):
                return False
            
            attack_detected = False
            attack_type = None
            
            # Adjust thresholds based on protection level
            threshold_multiplier = self.protection_level * 0.5  # Less aggressive multiplier
            
            # TCP based attacks
            if TCP in packet:
                # Check for SYN flood with adjusted threshold
                if packet[TCP].flags == 0x02 and self.check_syn_flood(ip_src, threshold_multiplier):
                    self.stats['syn_floods'] += 1
                    attack_detected = True
                    attack_type = "SYN Flood"
                
                # Check for port scan with adjusted threshold
                elif self.check_port_scan(ip_src, threshold_multiplier):
                    self.stats['port_scans'] += 1
                    attack_detected = True
                    attack_type = "Port Scan"
            
            # Check for UDP flood with adjusted threshold
            elif UDP in packet and self.check_udp_flood(ip_src, threshold_multiplier):
                self.stats['udp_floods'] += 1
                attack_detected = True
                attack_type = "UDP Flood"
            
            # Check for ICMP flood with adjusted threshold
            elif ICMP in packet and self.check_icmp_flood(ip_src, threshold_multiplier):
                self.stats['icmp_floods'] += 1
                attack_detected = True
                attack_type = "ICMP Flood"
            
            if attack_detected:
                logging.warning(f"{attack_type} detected from {ip_src}")
                print(f"{Fore.RED}[!] {attack_type} detected from: {ip_src}{Style.RESET_ALL}")
                return True
            
        return False

    def check_syn_flood(self, ip, threshold_multiplier=1.0):
        """Check for SYN flood with adjustable threshold"""
        syn_count = sum(1 for conn in self.connection_tracker.values() 
                       if conn['count'] > 0 and time.time() - conn['timestamp'] < 1)
        base_threshold = 500  # Increased base threshold
        return syn_count > (base_threshold * threshold_multiplier)

    def check_udp_flood(self, ip, threshold_multiplier=1.0):
        """Check for UDP flood with adjustable threshold"""
        if ip in self.packet_rates:
            rate = self.packet_rates[ip]['count']
            base_threshold = 2000  # Increased base threshold
            return rate > (base_threshold * threshold_multiplier)
        return False

    def check_icmp_flood(self, ip, threshold_multiplier=1.0):
        """Check for ICMP flood with adjustable threshold"""
        if ip in self.packet_rates:
            rate = self.packet_rates[ip]['count']
            base_threshold = 200  # Increased base threshold
            return rate > (base_threshold * threshold_multiplier)
        return False

    def check_port_scan(self, ip, threshold_multiplier=1.0):
        """Check for port scan with adjustable threshold"""
        unique_ports = set()
        current_time = time.time()
        scan_window = 60  # 60-second window
        
        for conn in self.connection_tracker:
            if ip in conn and current_time - self.connection_tracker[conn]['timestamp'] < scan_window:
                port = conn.split('-')[1].split(':')[-1]
                unique_ports.add(port)
        
        base_threshold = 50  # Increased base threshold
        return len(unique_ports) > (base_threshold * threshold_multiplier)

    def check_dns_amplification(self, packet):
        if UDP in packet and packet[UDP].dport == 53:
            if len(packet) > 1000:  # Large DNS response
                return True
        return False

    def check_fragment_attack(self, packet):
        if IP in packet and packet[IP].flags & 0x1:  # More fragments
            if packet[IP].frag > 0:  # Non-zero fragment offset
                return True
        return False

    def check_malformed_packet(self, packet):
        try:
            # Check for invalid IP header length
            if IP in packet and packet[IP].ihl * 4 > len(packet[IP]):
                return True
                
            # Check for invalid TCP options
            if TCP in packet and len(packet[TCP].options) > 40:
                return True
                
            # Check for invalid UDP length
            if UDP in packet and packet[UDP].len > len(packet[UDP]):
                return True
        except:
            return True
        return False

    def check_ip_spoofing(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            # Check if source IP is in private range
            if src_ip.startswith(('10.', '172.16.', '192.168.')):
                return False
            # Check if source IP is in blocked list
            if src_ip in self.blocked_ips:
                return True
        return False

    def check_ttl_anomalies(self, packet):
        """TTL değerindeki anomalileri kontrol et"""
        if IP in packet:
            ttl = packet[IP].ttl

            if ttl < 5 or ttl > 250:
                return True
        return False

    def check_tcp_sequence_prediction(self, packet):
        """TCP sequence tahmin saldırılarını kontrol et"""
        if TCP in packet:
            seq = packet[TCP].seq
            if seq == 0 or seq == 1:
                return True
        return False

    def block_ip(self, ip, reason="Attack detected"):
        """Block an IP address"""
        if ip in self.local_ips:
            logging.warning(f"Attempt to block local IP {ip} prevented")
            return False
            
        if self.is_ip_in_whitelist(ip):
            logging.warning(f"Attempt to block whitelisted IP: {ip} - Reason: {reason}")
            return False
        
        if ip not in self.blocked_ips:
            self.blocked_ips[ip] = {
                'timestamp': time.time(),
                'reason': reason
            }
            try:
                # Add blocking rule
                result = subprocess.run(
                    ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                    capture_output=True, text=True, check=True
                )
                logging.info(f"Blocked IP: {ip} - Reason: {reason}")
                
                # If IP is not in blacklist and should be permanently blocked
                if reason in ["Blacklisted", "Reputation based block"] and ip not in self.blacklist:
                    self.blacklist.append(ip)
                    self.save_ip_lists()
                return True
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to block IP {ip}: {e.stderr}")
                return False
            except Exception as e:
                logging.error(f"Error blocking IP {ip}: {str(e)}")
                return False
        return True

    def start_protection(self):
        if not self.interface:
            print(f"{Fore.RED}Error: No network interface selected!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please select a network interface first (Option 8).{Style.RESET_ALL}")
            input("\nPress Enter to return to main menu...")
            return False

        if not self.is_running:
            try:
                # Check if interface exists and is up
                interfaces = self.get_available_interfaces()
                interface_exists = False
                for iface in interfaces:
                    if iface['name'] == self.interface:
                        interface_exists = True
                        if iface['status'] != 'UP':
                            print(f"{Fore.RED}Error: Interface {self.interface} is DOWN!{Style.RESET_ALL}")
                            return False
                        break
                
                if not interface_exists:
                    print(f"{Fore.RED}Error: Interface {self.interface} not found!{Style.RESET_ALL}")
                    return False

                # If auto updates are enabled and it's time to check for updates
                if self.auto_update and time.time() - self.last_update_check > self.update_interval:
                    print(f"{Fore.YELLOW}Checking for updates...{Style.RESET_ALL}")
                    self.check_for_updates()

                self.is_running = True
                # Save start time
                self.start_time = time.time()
                
                # Clear screen and show startup banner
                os.system('clear')
                print(self.get_ascii_art())
                print(f"\n{Fore.GREEN}[+] Starting OpenMammoth Protection System{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Interface: {self.interface}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Protection Level: {self.protection_level}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Advanced Protection: {'Enabled' if self.advanced_protection else 'Disabled'}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Threat Intelligence: {'Enabled' if self.use_threat_intel else 'Disabled'}{Style.RESET_ALL}")
                print(f"\n{Fore.YELLOW}[*] Initializing protection modules...{Style.RESET_ALL}")
                
                def packet_capture():
                    try:
                        print(f"{Fore.GREEN}[+] Starting packet capture on {self.interface}...{Style.RESET_ALL}")
                        # Set Scapy logging level to reduce noise
                        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
                        
                        # Try to create L3 socket with appropriate privileges
                        conf.L3socket = L3RawSocket
                        
                        print(f"{Fore.GREEN}[+] Packet capture initialized successfully{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[+] Protection system is now active{Style.RESET_ALL}")
                        print(f"\n{Fore.CYAN}[*] Monitoring network traffic...{Style.RESET_ALL}")
                        
                        # Start sniffing with store=0 to avoid memory issues
                        sniff(iface=self.interface, 
                              prn=self.packet_handler, 
                              store=0,
                              filter="ip",  # Only capture IP packets
                              stop_filter=lambda p: not self.is_running)
                              
                    except PermissionError:
                        logging.error("Permission denied when starting packet capture. Make sure you're running as root.")
                        print(f"{Fore.RED}Error: Permission denied. Make sure you're running as root.{Style.RESET_ALL}")
                        self.is_running = False
                    except Exception as e:
                        logging.error(f"Error in packet capture: {str(e)}")
                        print(f"{Fore.RED}Error in packet capture: {str(e)}{Style.RESET_ALL}")
                        self.is_running = False
                
                def data_cleanup():
                    while self.is_running:
                        try:
                            self.cleanup_old_data()
                            time.sleep(self.cleanup_interval)
                        except Exception as e:
                            logging.error(f"Error in data cleanup: {str(e)}")
                
                def auto_updater():
                    while self.is_running and self.auto_update:
                        try:
                            if time.time() - self.last_update_check > self.update_interval:
                                logging.info("Running scheduled threat intelligence update")
                                self.update_threat_intel()
                            time.sleep(3600)  # Wait for 1 hour
                        except Exception as e:
                            logging.error(f"Error in auto updater: {str(e)}")
                
                # Start packet capture thread
                self.capture_thread = threading.Thread(target=packet_capture)
                self.capture_thread.daemon = True
                self.capture_thread.start()
                
                # Start cleanup thread
                self.cleanup_thread = threading.Thread(target=data_cleanup)
                self.cleanup_thread.daemon = True
                self.cleanup_thread.start()
                
                # Start update thread
                self.update_thread = threading.Thread(target=auto_updater)
                self.update_thread.daemon = True
                self.update_thread.start()
                
                # Wait a moment to see if packet capture starts successfully
                time.sleep(2)
                if not self.is_running:
                    print(f"{Fore.RED}Failed to start protection. Check the logs for details.{Style.RESET_ALL}")
                    return False
                
                print(f"{Fore.GREEN}Protection started successfully on {self.interface}{Style.RESET_ALL}")
                logging.info(f"Protection started on interface {self.interface}")
                return True
                
            except Exception as e:
                print(f"{Fore.RED}Error starting protection: {str(e)}{Style.RESET_ALL}")
                logging.error(f"Error starting protection: {str(e)}")
                self.is_running = False
                return False
        return False

    def stop_protection(self):
        if self.is_running:
            self.is_running = False
            print(f"{Fore.YELLOW}Stopping protection...{Style.RESET_ALL}")
            
            # Wait for a reasonable amount of time (max 5 seconds)
            if self.capture_thread and self.capture_thread.is_alive():
                try:
                    self.capture_thread.join(5)
                except Exception as e:
                    logging.error(f"Error stopping capture thread: {str(e)}")
            
            if self.cleanup_thread and self.cleanup_thread.is_alive():
                try:
                    self.cleanup_thread.join(5)
                except Exception as e:
                    logging.error(f"Error stopping cleanup thread: {str(e)}")
            
            if self.update_thread and self.update_thread.is_alive():
                try:
                    self.update_thread.join(5)
                except Exception as e:
                    logging.error(f"Error stopping update thread: {str(e)}")
            
            # Cleanup iptables rules, but only for temporary blocks (not blacklisted)
            for ip in list(self.blocked_ips.keys()):
                if ip not in self.blacklist:  # Keep blocking IPs in the blacklist
                    try:
                        subprocess.run(
                            ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                            capture_output=True, text=True, check=True
                        )
                        del self.blocked_ips[ip]
                    except Exception as e:
                        logging.error(f"Error removing iptables rule for {ip}: {str(e)}")
            
            # Clean up resources
            try:
                # Scapy sockets might still be open
                conf.L2socket = None
                conf.L3socket = None
            except Exception as e:
                logging.error(f"Error cleaning up sockets: {str(e)}")
            
            logging.info("Protection stopped")
            return True
        return False

    def cleanup_old_data(self):
        """Clean up old data to reduce memory usage"""
        current_time = time.time()
        self.last_cleanup_time = current_time
        
        # Connection tracker cleanup
        expired_connections = []
        for key, data in self.connection_tracker.items():
            # Clean up connections older than 10 minutes
            if current_time - data['timestamp'] > 600:
                expired_connections.append(key)
        
        # Keep at most 1000 connection records
        if len(self.connection_tracker) > 1000:
            connection_items = sorted(self.connection_tracker.items(), 
                                      key=lambda x: x[1]['timestamp'])
            # List of oldest connections
            extra_connections = connection_items[:len(connection_items) - 1000]
            expired_connections.extend([k for k, v in extra_connections])
        
        # Clean up
        for key in expired_connections:
            if key in self.connection_tracker:
                del self.connection_tracker[key]
        
        # Packet rates cleanup
        expired_rates = []
        for ip, data in self.packet_rates.items():
            # Clean up data older than 2 minutes
            if current_time - data['timestamp'] > 120:
                expired_rates.append(ip)
        
        # Clean up
        for ip in expired_rates:
            if ip in self.packet_rates:
                del self.packet_rates[ip]
        
        # Log
        logging.info(f"Data cleanup completed - Removed {len(expired_connections)} connections and {len(expired_rates)} packet rates")

    def display_menu(self):
        while True:
            os.system('clear')
            print(self.get_ascii_art())
            print(f"\n{Fore.CYAN}=== OpenMammoth Network Protection ==={Style.RESET_ALL}")
            print(f"{Fore.GREEN}1. Start Protection{Style.RESET_ALL}")
            print(f"{Fore.RED}2. Stop Protection{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}3. Protection Status{Style.RESET_ALL}")
            print(f"{Fore.BLUE}4. Settings{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}5. View Statistics{Style.RESET_ALL}")
            print(f"{Fore.CYAN}6. View Blocked IPs{Style.RESET_ALL}")
            print(f"{Fore.GREEN}7. Advanced Options{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}8. Configure Network Interfaces{Style.RESET_ALL}")
            print(f"{Fore.CYAN}9. Help{Style.RESET_ALL}")
            print(f"{Fore.CYAN}10. About{Style.RESET_ALL}")
            print(f"{Fore.RED}0. Exit{Style.RESET_ALL}")
            
            choice = input("\nEnter your choice (0-10): ")
            
            if choice == "1":
                self.start_protection()
            elif choice == "2":
                self.stop_protection()
            elif choice == "3":
                self.view_protection_status()
            elif choice == "4":
                self.settings_menu()
            elif choice == "5":
                self.view_statistics()
            elif choice == "6":
                self.view_blocked_ips()
            elif choice == "7":
                self.advanced_options()
            elif choice == "8":
                self.configure_interfaces()
            elif choice == "9":
                self.show_help()
            elif choice == "10":
                self.show_about()
            elif choice == "0":
                if self.is_running:
                    self.stop_protection()
                print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    def settings_menu(self):
        while True:
            print(f"\n{Fore.CYAN}=== Settings ==={Style.RESET_ALL}")
            print(f"1. Protection Level (Current: {self.protection_level})")
            print(f"2. Advanced Protection (Current: {'Enabled' if self.advanced_protection else 'Disabled'})")
            print(f"3. Debug Mode (Current: {'Enabled' if self.debug_mode else 'Disabled'})")
            print(f"4. Network Interface (Current: {self.interface if self.interface else 'Not selected'})")
            print(f"5. Threat Intelligence (Current: {'Enabled' if self.use_threat_intel else 'Disabled'})")
            print(f"6. Auto Updates (Current: {'Enabled' if self.auto_update else 'Disabled'})")
            print(f"7. Reset IPTables Rules")
            print("8. Back to Main Menu")
            
            choice = input("\nEnter your choice (1-8): ")
            
            if choice == "1":
                level = input("Enter protection level (1-4): ")
                if level.isdigit() and 1 <= int(level) <= 4:
                    self.protection_level = int(level)
                    self.save_config()
                    print(f"{Fore.GREEN}Protection level set to {self.protection_level}{Style.RESET_ALL}")
            elif choice == "2":
                self.advanced_protection = not self.advanced_protection
                self.save_config()
                status = "enabled" if self.advanced_protection else "disabled"
                print(f"{Fore.GREEN}Advanced protection {status}{Style.RESET_ALL}")
            elif choice == "3":
                self.debug_mode = not self.debug_mode
                self.setup_logging()
                self.save_config()
                status = "enabled" if self.debug_mode else "disabled"
                print(f"{Fore.GREEN}Debug mode {status}{Style.RESET_ALL}")
            elif choice == "4":
                if self.select_interface():
                    self.save_config()
            elif choice == "5":
                self.use_threat_intel = not self.use_threat_intel
                self.save_config()
                status = "enabled" if self.use_threat_intel else "disabled"
                print(f"{Fore.GREEN}Threat intelligence {status}{Style.RESET_ALL}")
                if self.use_threat_intel and (not self.threat_intel_db or time.time() - self.last_update_check > self.update_interval):
                    print(f"{Fore.YELLOW}Updating threat intelligence database...{Style.RESET_ALL}")
                    self.update_threat_intel()
            elif choice == "6":
                self.auto_update = not self.auto_update
                self.save_config()
                status = "enabled" if self.auto_update else "disabled"
                print(f"{Fore.GREEN}Auto updates {status}{Style.RESET_ALL}")
                if self.auto_update and time.time() - self.last_update_check > self.update_interval:
                    print(f"{Fore.YELLOW}Checking for updates...{Style.RESET_ALL}")
                    self.check_for_updates()
            elif choice == "7":
                self.reset_iptables_rules()
            elif choice == "8":
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    def view_statistics(self):
        """Show protection statistics"""
        try:
            print(f"\n{Fore.CYAN}=== Protection Statistics ==={Style.RESET_ALL}")
            
            # Calculate uptime
            if hasattr(self, 'start_time') and self.is_running:
                uptime = time.time() - self.start_time
                hours, remainder = divmod(uptime, 3600)
                minutes, seconds = divmod(remainder, 60)
                print(f"Uptime: {int(hours)}h {int(minutes)}m {int(seconds)}s")
            
            print(f"Total Packets: {self.stats['total_packets']}")
            print(f"Blocked Packets: {self.stats['blocked_packets']}")
            print(f"Attacks Detected: {self.stats['attacks_detected']}")
            print(f"Port Scans: {self.stats['port_scans']}")
            print(f"SYN Floods: {self.stats['syn_floods']}")
            print(f"UDP Floods: {self.stats['udp_floods']}")
            print(f"ICMP Floods: {self.stats['icmp_floods']}")
            print(f"DNS Amplification: {self.stats['dns_amplification']}")
            print(f"Fragment Attacks: {self.stats['fragment_attacks']}")
            print(f"Malformed Packets: {self.stats['malformed_packets']}")
            print(f"Spoofed IPs: {self.stats['spoofed_ips']}")
            print(f"Threat Intel Blocks: {self.stats['threat_intel_blocks']}")
            print(f"Reputation Blocks: {self.stats['reputation_blocks']}")
            
            # Packet rates and active connections
            if self.is_running:
                print(f"\nActive connections: {len(self.connection_tracker)}")
                
            input("\nPress Enter to return to main menu...")
        except Exception as e:
            logging.error(f"Error displaying statistics: {str(e)}")
            print(f"{Fore.RED}Error displaying statistics: {str(e)}{Style.RESET_ALL}")

    def view_blocked_ips(self):
        """View blocked IP addresses"""
        os.system('clear')  # Clear screen first
        print(f"\n{Fore.CYAN}=== Blocked IP Addresses ==={Style.RESET_ALL}")
        
        if not self.blocked_ips:
            print(f"\n{Fore.YELLOW}No IPs are currently blocked.{Style.RESET_ALL}")
        else:
            print(f"\nTotal Blocked IPs: {len(self.blocked_ips)}\n")
            print(f"{Fore.CYAN}{'IP Address':<20} {'Duration':<15} {'Reason':<30}{Style.RESET_ALL}")
            print("-" * 65)
            
            current_time = time.time()
            for ip, info in self.blocked_ips.items():
                duration = current_time - info['timestamp']
                # Convert duration to human readable format
                if duration < 60:
                    duration_str = f"{int(duration)}s"
                elif duration < 3600:
                    duration_str = f"{int(duration/60)}m"
                else:
                    duration_str = f"{int(duration/3600)}h"
                
                print(f"{ip:<20} {duration_str:<15} {info['reason']:<30}")
        
        print("\nPress Enter to return to main menu...")
        input()

    def advanced_options(self):
        while True:
            print(f"\n{Fore.CYAN}=== Advanced Options ==={Style.RESET_ALL}")
            print("1. View Detailed Logs")
            print("2. Export Statistics")
            print("3. Clear Blocked IPs")
            print("4. Manage Whitelist")
            print("5. Manage Blacklist")
            print("6. Update Threat Intelligence")
            print("7. Firewall Settings")
            print("8. Back to Main Menu")
            
            choice = input("\nEnter your choice (1-8): ")
            
            if choice == "1":
                self.view_logs()
            elif choice == "2":
                self.export_statistics()
            elif choice == "3":
                self.clear_blocked_ips()
            elif choice == "4":
                self.manage_whitelist()
            elif choice == "5":
                self.manage_blacklist()
            elif choice == "6":
                self.update_threat_intel()
                print(f"{Fore.GREEN}Threat intelligence database updated.{Style.RESET_ALL}")
            elif choice == "7":
                self.firewall_settings()
            elif choice == "8":
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    def view_logs(self):
        """View detailed logs"""
        os.system('clear')
        try:
            log_path = os.path.join(self.config_dir, 'openmammoth.log')
            if os.path.exists(log_path):
                print(f"\n{Fore.CYAN}=== Recent Logs ==={Style.RESET_ALL}")
                with open(log_path, 'r') as f:
                    logs = f.readlines()
                    # Show last 20 lines with proper formatting
                    for line in logs[-20:]:
                        # Color code different log levels
                        if "ERROR" in line:
                            print(f"{Fore.RED}{line.strip()}{Style.RESET_ALL}")
                        elif "WARNING" in line:
                            print(f"{Fore.YELLOW}{line.strip()}{Style.RESET_ALL}")
                        else:
                            print(line.strip())
            else:
                print(f"{Fore.RED}No log file found.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error reading log file: {str(e)}{Style.RESET_ALL}")
        
        input("\nPress Enter to return to Advanced Options...")

    def export_statistics(self):
        """Export statistics to a file"""
        try:
            os.system('clear')
            print(f"\n{Fore.CYAN}=== Export Statistics ==={Style.RESET_ALL}")
            
            # Create export data
            export_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "stats": self.stats,
                "configuration": {
                    "protection_level": self.protection_level,
                    "advanced_protection": self.advanced_protection,
                    "interface": self.interface,
                    "threat_intel_enabled": self.use_threat_intel
                },
                "blocked_ips": len(self.blocked_ips),
                "whitelisted_ips": len(self.whitelist),
                "blacklisted_ips": len(self.blacklist)
            }
            
            # Create filename with timestamp
            filename = f"openmammoth_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=4)
            
            print(f"\n{Fore.GREEN}[+] Statistics exported successfully to: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error exporting statistics: {str(e)}{Style.RESET_ALL}")
        
        input("\nPress Enter to return to Advanced Options...")

    def firewall_settings(self):
        """Manage firewall settings"""
        while True:
            os.system('clear')
            print(f"\n{Fore.CYAN}=== Firewall Settings ==={Style.RESET_ALL}")
            print("1. View Current Firewall Rules")
            print("2. Reset All Firewall Rules")
            print("3. Apply Basic Protection Rules")
            print("4. Back to Advanced Options")
            
            choice = input("\nEnter your choice (1-4): ")
            
            if choice == "1":
                self.view_firewall_rules()
            elif choice == "2":
                self.reset_iptables_rules()
            elif choice == "3":
                self.apply_basic_protection()
                print(f"{Fore.GREEN}Basic protection rules applied.{Style.RESET_ALL}")
                input("\nPress Enter to continue...")
            elif choice == "4":
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
                input("\nPress Enter to continue...")

    def view_firewall_rules(self):
        """View current firewall rules"""
        os.system('clear')
        try:
            print(f"\n{Fore.CYAN}=== Current Firewall Rules ==={Style.RESET_ALL}\n")
            result = subprocess.run(['iptables', '-L', '-n', '--line-numbers'], capture_output=True, text=True)
            
            # Format and colorize the output
            for line in result.stdout.split('\n'):
                if "Chain" in line:
                    print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
                elif "target" in line:
                    print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
                elif "DROP" in line:
                    print(f"{Fore.RED}{line}{Style.RESET_ALL}")
                elif "ACCEPT" in line:
                    print(f"{Fore.GREEN}{line}{Style.RESET_ALL}")
                else:
                    print(line)
        except Exception as e:
            print(f"{Fore.RED}Error viewing firewall rules: {str(e)}{Style.RESET_ALL}")
        
        input("\nPress Enter to return to Firewall Settings...")

    def reset_iptables_rules(self):
        """Reset all IPTables rules and restore default policy with enhanced confirmations"""
        try:
            # First confirmation
            print(f"\n{Fore.RED}WARNING: This will reset all IPTables rules!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}This action will:{Style.RESET_ALL}")
            print("1. Clear all existing firewall rules")
            print("2. Reset all chains to default policy")
            print("3. Remove all custom chains")
            confirm1 = input("\nProceed? [y/N]: ").lower() or 'n'
            
            if confirm1 != 'y':
                print(f"{Fore.YELLOW}Operation cancelled.{Style.RESET_ALL}")
                return
            
            # Second confirmation - Tor warning
            print(f"\n{Fore.RED}IMPORTANT TOR NETWORK WARNING:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Resetting IPTables rules will:{Style.RESET_ALL}")
            print("1. Disable any existing Tor routing rules")
            print("2. Potentially expose your real IP address")
            print("3. Break anonymity if you're using Tor")
            confirm2 = input("\nConfirm you are NOT using Tor? [y/N]: ").lower() or 'n'
            
            if confirm2 != 'y':
                print(f"{Fore.YELLOW}Operation cancelled for your security.{Style.RESET_ALL}")
                return
            
            # Final confirmation
            print(f"\n{Fore.RED}FINAL CONFIRMATION:{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please confirm that:{Style.RESET_ALL}")
            print("1. You understand all current firewall rules will be deleted")
            print("2. You are NOT using Tor for anonymity")
            print("3. You accept the security implications")
            confirm3 = input("\nAre you absolutely sure? [y/N]: ").lower() or 'n'
            
            if confirm3 != 'y':
                print(f"{Fore.YELLOW}Operation cancelled.{Style.RESET_ALL}")
                return
            
            # Proceed with reset
            print(f"\n{Fore.YELLOW}Resetting IPTables rules...{Style.RESET_ALL}")
            
            # Flush all rules
            subprocess.run(['iptables', '-F'], check=True)
            subprocess.run(['iptables', '-X'], check=True)
            subprocess.run(['iptables', '-t', 'nat', '-F'], check=True)
            subprocess.run(['iptables', '-t', 'nat', '-X'], check=True)
            subprocess.run(['iptables', '-t', 'mangle', '-F'], check=True)
            subprocess.run(['iptables', '-t', 'mangle', '-X'], check=True)
            
            # Set default policies to ACCEPT
            subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
            
            # Clear blocked IPs list
            self.blocked_ips.clear()
            
            print(f"{Fore.GREEN}Successfully reset all IPTables rules.{Style.RESET_ALL}")
            logging.info("IPTables rules reset by user after triple confirmation")
            
        except Exception as e:
            print(f"{Fore.RED}Error resetting IPTables rules: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Error resetting IPTables rules: {str(e)}")
        
        input("\nPress Enter to continue...")

    def apply_basic_protection(self):
        """Apply basic protection rules"""
        try:
            # First clean up existing rules
            self.reset_iptables_rules()
            
            # Set default policies
            subprocess.run(['iptables', '-P', 'INPUT', 'DROP'], check=True)
            subprocess.run(['iptables', '-P', 'FORWARD', 'DROP'], check=True)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
            
            # Allow loopback traffic
            subprocess.run(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=True)
            
            # Allow established connections
            subprocess.run(['iptables', '-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], check=True)
            
            # Allow all traffic from local network
            for network in ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']:
                subprocess.run(['iptables', '-A', 'INPUT', '-s', network, '-j', 'ACCEPT'], check=True)
            
            # Allow common services
            common_ports = [
                ('tcp', '22'),    # SSH
                ('tcp', '80'),    # HTTP
                ('tcp', '443'),   # HTTPS
                ('udp', '53'),    # DNS
                ('tcp', '53'),    # DNS
                ('udp', '67:68'), # DHCP
                ('tcp', '21'),    # FTP
                ('tcp', '990'),   # FTPS
                ('tcp', '143'),   # IMAP
                ('tcp', '993'),   # IMAPS
                ('tcp', '110'),   # POP3
                ('tcp', '995'),   # POP3S
                ('tcp', '25'),    # SMTP
                ('tcp', '587'),   # SMTP
                ('tcp', '465'),   # SMTPS
                ('udp', '123'),   # NTP
            ]
            
            for proto, port in common_ports:
                subprocess.run(['iptables', '-A', 'INPUT', '-p', proto, '--dport', port, '-j', 'ACCEPT'], check=True)
            
            # Allow ping requests with rate limiting
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'icmp', '--icmp-type', 'echo-request', 
                          '-m', 'limit', '--limit', '1/s', '-j', 'ACCEPT'], check=True)
            
            # Block IPs in the blacklist
            for ip in self.blacklist:
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                self.blocked_ips[ip] = {
                    'timestamp': time.time(),
                    'reason': 'Blacklisted'
                }
            
            logging.info("Basic protection rules applied")
            print(f"{Fore.GREEN}Basic protection rules applied successfully.{Style.RESET_ALL}")
            
        except Exception as e:
            logging.error(f"Error applying basic protection rules: {str(e)}")
            print(f"{Fore.RED}Error applying protection rules: {str(e)}{Style.RESET_ALL}")

    def show_help(self):
        print(f"\n{Fore.CYAN}=== OpenMammoth Help ==={Style.RESET_ALL}")
        print("OpenMammoth is a network protection tool that helps secure your system")
        print("against various types of cyber attacks.")
        print("\nMain Features:")
        print("- Real-time packet analysis")
        print("- Multiple protection levels")
        print("- Advanced attack detection")
        print("- IP blocking system")
        print("- Detailed statistics")
        print("- Whitelist and blacklist management")
        print("- Threat intelligence integration")
        print("- Automatic updates")
        print("- Comprehensive firewall rules management")
        print("\nProtection Levels:")
        print("1. Basic - Minimal protection, low resource usage")
        print("2. Standard - Balanced protection")
        print("3. Enhanced - Strong protection")
        print("4. Extreme - Maximum protection")
        print("\nAdvanced Protection:")
        print("When enabled, additional security checks are performed including:")
        print("- TTL anomaly detection")
        print("- TCP sequence prediction attacks")
        print("- Stealth scan detection (Null, FIN, XMAS scans)")
        print("\nThreat Intelligence:")
        print("When enabled, OpenMammoth uses external threat intelligence")
        print("to identify and block known malicious IP addresses.")
        print("\nFor more information, visit the GitHub repository.")
        
        input("\nPress Enter to return to main menu...")

    def show_about(self):
        print(f"\n{Fore.CYAN}=== About OpenMammoth ==={Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Version: 2.0{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Author: root0emir{Style.RESET_ALL}")
        print(f"{Fore.BLUE}License: MIT{Style.RESET_ALL}")
        print("\nOpenMammoth is a powerful network protection tool designed to")
        print("secure your system against various types of cyber attacks.")
        print("This version is a OpenMammoth Securonis Edition Forked and simplified for Securonis Linux ")
        print("\nFeatures:")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Real-time packet analysis")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Multiple protection levels")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Advanced attack detection")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} IP blocking system")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Detailed statistics")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Customizable settings")
        print("\nSupported Attack Types:")
        print(f"{Fore.RED}•{Style.RESET_ALL} Port Scanning")
        print(f"{Fore.RED}•{Style.RESET_ALL} SYN Flood")
        print(f"{Fore.RED}•{Style.RESET_ALL} UDP Flood")
        print(f"{Fore.RED}•{Style.RESET_ALL} ICMP Flood")
        print(f"{Fore.RED}•{Style.RESET_ALL} DNS Amplification")
        print(f"{Fore.RED}•{Style.RESET_ALL} Fragment Attacks")
        print(f"{Fore.RED}•{Style.RESET_ALL} Malformed Packets")
        print(f"{Fore.RED}•{Style.RESET_ALL} IP Spoofing")
        print(f"\n{Fore.CYAN}GitHub: https://github.com/Securonis/OpenMammoth {Style.RESET_ALL}")
        input("\nPress Enter to return to main menu...")

    def get_available_interfaces(self):
        """Get available network interfaces"""
        interfaces = []
        try:
            # Use ip command to get interface information
            ip_output = subprocess.check_output(['ip', 'addr', 'show'], text=True)
            current_interface = None
            
            for line in ip_output.split('\n'):
                # Match interface line
                if line and not line.startswith(' '):
                    interface_match = re.match(r'\d+:\s+([^:@]+)[:.@]', line)
                    if interface_match:
                        current_interface = {
                            'name': interface_match.group(1),
                            'ip': '',
                            'mac': '',
                            'status': 'DOWN'
                        }
                        if 'UP' in line:
                            current_interface['status'] = 'UP'
                        interfaces.append(current_interface)
                
                # Match IP address line
                elif current_interface and 'inet ' in line:
                    ip_match = re.search(r'inet\s+([0-9.]+)/', line)
                    if ip_match:
                        current_interface['ip'] = ip_match.group(1)
                
                # Match MAC address line
                elif current_interface and 'link/ether' in line:
                    mac_match = re.search(r'link/ether\s+([0-9a-fA-F:]+)', line)
                    if mac_match:
                        current_interface['mac'] = mac_match.group(1)

            # Filter out interfaces without IP addresses (except lo)
            interfaces = [iface for iface in interfaces if iface['ip'] or iface['name'] == 'lo']
            
            if not interfaces:
                logging.warning("No network interfaces found with IP addresses")
            else:
                logging.info(f"Found {len(interfaces)} network interfaces")
                
            return interfaces
            
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running ip command: {str(e)}")
            return []
        except Exception as e:
            logging.error(f"Error getting network interfaces: {str(e)}")
            return []

    def display_interfaces(self):
        """Display network interfaces"""
        print(f"\n{Fore.CYAN}=== Available Network Interfaces ==={Style.RESET_ALL}")
        if not self.available_interfaces:
            print(f"{Fore.RED}Warning: No network interfaces found!{Style.RESET_ALL}")
            return False
        
        for idx, iface in enumerate(self.available_interfaces, 1):
            print(f"{idx}. {iface['name']}")
            print(f"   IP: {iface['ip']}")
            print(f"   MAC: {iface['mac']}")
            print(f"   Status: {iface['status']}")
            print("-" * 40)
        return True

    def select_interface(self):
        """Select network interface"""
        if not self.available_interfaces:
            print(f"{Fore.RED}Warning: No network interfaces found!{Style.RESET_ALL}")
            return False
        
        if not self.display_interfaces():
            return False
        
        while True:
            try:
                choice = input("\nSelect interface (1-{}) or 'q' to quit: ".format(len(self.available_interfaces)))
                if choice.lower() == 'q':
                    return False
                
                idx = int(choice) - 1
                if 0 <= idx < len(self.available_interfaces):
                    self.interface = self.available_interfaces[idx]['name']
                    print(f"{Fore.GREEN}Selected interface: {self.interface}{Style.RESET_ALL}")
                    return True
                else:
                    print(f"{Fore.RED}Invalid selection! Please select an interface from the list.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Please enter a valid number!{Style.RESET_ALL}")

    def load_threat_intel(self):
        try:
            intel_path = os.path.join(self.config_dir, 'threat_intel.json')
            if os.path.exists(intel_path):
                with open(intel_path, 'r') as f:
                    self.threat_intel_db = json.load(f)
                    logging.info(f"Loaded {len(self.threat_intel_db)} threat intelligence entries")
            else:

                self.update_threat_intel()
        except Exception as e:
            logging.error(f"Error loading threat intelligence: {str(e)}")
            self.threat_intel_db = {}

    def update_threat_intel(self):
        """Update threat intelligence database"""
        try:
            # This function requires internet connection
            if not self.check_internet_connection():
                logging.warning("No internet connection available for threat intel update")
                return False
                
            logging.info("Updating threat intelligence database...")
            
            # Fetch threat list from trusted sources (example URLs)
            sources = [
                "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
            ]
            
            updated_db = {}
            sources_success = 0
            for source in sources:
                try:
                    response = requests.get(source, timeout=10)
                    if response.status_code == 200:
                        # Process IP addresses line by line
                        count_before = len(updated_db)
                        for line in response.text.split("\n"):
                            line = line.strip()
                            # Skip comment lines and empty lines
                            if not line or line.startswith("#"):
                                continue
                            
                            # Split IP address and other information
                            parts = line.split()
                            ip = parts[0]
                            
                            # Validate IP address
                            try:
                                ipaddress.ip_address(ip)
                                # Don't add local IPs and whitelisted IPs as threats
                                if ip not in self.local_ips and ip not in self.whitelist:
                                    updated_db[ip] = {
                                        "source": source,
                                        "timestamp": time.time(),
                                        "score": 100  # Default threat score
                                    }
                            except ValueError:
                                continue
                        
                        sources_success += 1
                        ips_added = len(updated_db) - count_before
                        logging.info(f"Added {ips_added} IPs from {source}")
                    else:
                        logging.warning(f"Failed to fetch threat data from {source}: Status code {response.status_code}")
                except Exception as e:
                    logging.error(f"Error fetching threat data from {source}: {str(e)}")
            
            if updated_db and sources_success > 0:
                old_count = len(self.threat_intel_db)
                self.threat_intel_db = updated_db
                
                # Save database to disk
                intel_path = os.path.join(self.config_dir, 'threat_intel.json')
                try:
                    with open(intel_path, 'w') as f:
                        json.dump(self.threat_intel_db, f, indent=4)
                    logging.info(f"Updated threat intelligence database with {len(updated_db)} entries (was {old_count})")
                except Exception as e:
                    logging.error(f"Error saving threat intelligence database: {str(e)}")
                    
                self.last_update_check = time.time()
                self.save_config()
                return True
            else:
                logging.warning("No threat intelligence data was updated")
                return False
        except Exception as e:
            logging.error(f"Error updating threat intelligence: {str(e)}")
            return False

    def check_internet_connection(self):
        """Check internet connection"""
        try:
            # Try to connect to Google DNS
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except OSError:
            try:
                # Try to connect to Cloudflare DNS
                socket.create_connection(("1.1.1.1", 53), timeout=3)
                return True
            except OSError:
                pass
        except Exception:
            pass
        return False

    def load_ip_lists(self):
        """Load whitelist and blacklist"""
        try:
            # Load whitelist file
            whitelist_path = os.path.join(self.config_dir, 'whitelist.txt')
            if os.path.exists(whitelist_path):
                with open(whitelist_path, 'r') as f:
                    self.whitelist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                logging.info(f"Loaded {len(self.whitelist)} whitelisted IPs")
            
            # Load blacklist file
            blacklist_path = os.path.join(self.config_dir, 'blacklist.txt')
            if os.path.exists(blacklist_path):
                with open(blacklist_path, 'r') as f:
                    self.blacklist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                logging.info(f"Loaded {len(self.blacklist)} blacklisted IPs")
                
                # Block IPs in the blacklist
                for ip in self.blacklist:
                    if ip not in self.blocked_ips:
                        self.block_ip(ip, reason="Blacklisted")
        except Exception as e:
            logging.error(f"Error loading IP lists: {str(e)}")

    def save_ip_lists(self):
        """Save whitelist and blacklist"""
        try:
            # Save whitelist
            whitelist_path = os.path.join(self.config_dir, 'whitelist.txt')
            with open(whitelist_path, 'w') as f:
                f.write("# OpenMammoth Whitelist\n")
                f.write("# Format: One IP per line\n")
                for ip in self.whitelist:
                    f.write(f"{ip}\n")
            
            # Save blacklist
            blacklist_path = os.path.join(self.config_dir, 'blacklist.txt')
            with open(blacklist_path, 'w') as f:
                f.write("# OpenMammoth Blacklist\n")
                f.write("# Format: One IP per line\n")
                for ip in self.blacklist:
                    f.write(f"{ip}\n")
            
            logging.info("IP lists saved successfully")
        except Exception as e:
            logging.error(f"Error saving IP lists: {str(e)}")

    def is_ip_in_blacklist(self, ip):
        """Check if IP is in blacklist"""
        return ip in self.blacklist

    def is_ip_in_whitelist(self, ip):
        """Check if IP is in whitelist"""
        return ip in self.whitelist

    def is_ip_in_threat_intel(self, ip):
        """Check if IP is in threat intelligence database"""
        return ip in self.threat_intel_db

    def check_ip_reputation(self, ip):
        """Check IP reputation"""
        if self.is_ip_in_whitelist(ip):
            return False  # Not a threat if in whitelist
        
        if self.is_ip_in_blacklist(ip):
            self.stats['reputation_blocks'] += 1
            return True  # Threat if in blacklist
        
        if self.use_threat_intel and self.is_ip_in_threat_intel(ip):
            self.stats['threat_intel_blocks'] += 1
            return True  # Threat if in threat intelligence
        
        return False  # Not a threat in other cases

    def check_for_updates(self):
        """Check for new threat database updates"""
        try:
            current_time = time.time()
            
            # If enough time has passed since the last update check
            if current_time - self.last_update_check > self.update_interval:
                logging.info("Checking for threat intelligence updates")
                
                # Check internet connection
                if not self.check_internet_connection():
                    logging.error("No internet connection available for update check")
                    return False
                
                # Update threat intelligence database
                if self.use_threat_intel:
                    if self.update_threat_intel():
                        print(f"{Fore.GREEN}Threat intelligence database updated successfully.{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}Failed to update threat intelligence database.{Style.RESET_ALL}")
                
                # Save last update time
                self.last_update_check = current_time
                self.save_config()
                
                return True
        except Exception as e:
            logging.error(f"Error checking for updates: {str(e)}")
        
        return False

    def add_to_whitelist(self, ip):
        """Add IP address to whitelist"""
        try:
            # Validate IP address format
            ipaddress.ip_address(ip)
            
            # If IP is not already in whitelist
            if ip not in self.whitelist:
                self.whitelist.append(ip)
                
                # If IP is in blacklist or blocked IPs, remove it
                if ip in self.blacklist:
                    self.blacklist.remove(ip)
                
                if ip in self.blocked_ips:
                    # Remove blocking rule
                    try:
                        subprocess.run(
                            ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                            capture_output=True, text=True, check=True
                        )
                    except Exception:
                        pass
                    del self.blocked_ips[ip]
                
                # Save lists
                self.save_ip_lists()
                
                logging.info(f"Added IP to whitelist: {ip}")
                return True
            return False
        except ValueError:
            logging.error(f"Invalid IP address format: {ip}")
            return False
        except Exception as e:
            logging.error(f"Error adding IP to whitelist: {str(e)}")
            return False

    def add_to_blacklist(self, ip):
        """Add IP address to blacklist"""
        try:
            # Validate IP address format
            ipaddress.ip_address(ip)
            
            # If IP is not already in blacklist
            if ip not in self.blacklist:
                # If IP is in whitelist, warn and cancel
                if ip in self.whitelist:
                    logging.warning(f"Cannot blacklist whitelisted IP: {ip}")
                    return False
                
                self.blacklist.append(ip)
                
                # If IP is not already blocked, block it
                if ip not in self.blocked_ips:
                    self.block_ip(ip, reason="Blacklisted")
                
                # Save lists
                self.save_ip_lists()
                
                logging.info(f"Added IP to blacklist: {ip}")
                return True
            return False
        except ValueError:
            logging.error(f"Invalid IP address format: {ip}")
            return False
        except Exception as e:
            logging.error(f"Error adding IP to blacklist: {str(e)}")
            return False

    def check_system_requirements(self):
        """Check basic system requirements"""
        # Check if iptables is installed
        try:
            iptables_check = subprocess.run(
                ['which', 'iptables'], 
                capture_output=True, 
                text=True
            )
            if iptables_check.returncode != 0:
                print(f"{Fore.RED}Error: iptables is not installed!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Please install iptables: 'sudo apt-get install iptables'{Style.RESET_ALL}")
                sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}Error checking system requirements: {str(e)}{Style.RESET_ALL}")
            
        # Check if we have root privileges
        if os.geteuid() != 0:
            print(f"{Fore.RED}Error: This program must be run as root.{Style.RESET_ALL}")
            sys.exit(1)
    
    def detect_local_ips(self):
        """Detect local IP addresses and add them to whitelist"""
        try:
            # Get all network interfaces
            for iface in self.available_interfaces:
                if 'ip' in iface and iface['ip'] != '127.0.0.1':
                    self.local_ips.append(iface['ip'])
                    # Automatically add local IPs to whitelist
                    if iface['ip'] not in self.whitelist:
                        self.whitelist.append(iface['ip'])
            
            # Loopback address should always be in whitelist
            if '127.0.0.1' not in self.whitelist:
                self.whitelist.append('127.0.0.1')
                
            if self.local_ips:
                logging.info(f"Detected local IPs: {', '.join(self.local_ips)}")
        except Exception as e:
            logging.error(f"Error detecting local IPs: {str(e)}")

    def configure_interfaces(self):
        """Configure network interfaces"""
        print(f"\n{Fore.CYAN}=== Network Interface Configuration ==={Style.RESET_ALL}")
        
        # Refresh available interfaces
        self.available_interfaces = self.get_available_interfaces()
        
        if not self.available_interfaces:
            print(f"{Fore.RED}Error: No network interfaces detected!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please check your network connections and try again.{Style.RESET_ALL}")
            print("\nPossible solutions:")
            print("1. Make sure your network hardware is properly connected")
            print("2. Run 'ip link' or 'ifconfig' to check interface status")
            print("3. Use 'ip link set <interface> up' to bring up interfaces")
            input("\nPress Enter to return to main menu...")
            return
        
        # Display available interfaces and select one
        self.select_interface()

    def view_protection_status(self):
        """View current protection status"""
        os.system('clear')
        print(f"\n{Fore.CYAN}=== Protection Status ==={Style.RESET_ALL}")
        
        if self.is_running:
            uptime = time.time() - self.start_time
            hours, remainder = divmod(uptime, 3600)
            minutes, seconds = divmod(remainder, 60)
            
            print(f"\n{Fore.GREEN}[+] Protection Status: ACTIVE{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Interface: {self.interface}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Protection Level: {self.protection_level}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Advanced Protection: {'Enabled' if self.advanced_protection else 'Disabled'}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Threat Intelligence: {'Enabled' if self.use_threat_intel else 'Disabled'}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Uptime: {int(hours)}h {int(minutes)}m {int(seconds)}s{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Current Statistics:{Style.RESET_ALL}")
            print(f"Total Packets: {self.stats['total_packets']}")
            print(f"Blocked Packets: {self.stats['blocked_packets']}")
            print(f"Attacks Detected: {self.stats['attacks_detected']}")
            print(f"Active Blocks: {len(self.blocked_ips)}")
        else:
            print(f"\n{Fore.RED}[!] Protection Status: INACTIVE{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Use 'Start Protection' to enable network protection.{Style.RESET_ALL}")
        
        input("\nPress Enter to return to main menu...")

    def is_local_network(self, ip):
        """Enhanced check for local network IPs"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IP is in local networks list
            if ip in self.local_ips:
                return True
            
            # Check common local IP patterns
            if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                return True
            
            # Check if IP is router/gateway
            if ip.endswith('.1') or ip.endswith('.254'):
                return True
            
            # Check private IP ranges
            return any([
                ip_obj in ipaddress.ip_network('10.0.0.0/8'),
                ip_obj in ipaddress.ip_network('172.16.0.0/12'),
                ip_obj in ipaddress.ip_network('192.168.0.0/16'),
                ip_obj in ipaddress.ip_network('127.0.0.0/8'),
                ip_obj in ipaddress.ip_network('169.254.0.0/16')  # Link-local addresses
            ])
        except ValueError:
            return False

def main():
    if os.geteuid() != 0:
        print(f"{Fore.RED}Error: This program must be run as root.{Style.RESET_ALL}")
        sys.exit(1)
    
    tool = OpenMammoth()
    tool.display_menu()

if __name__ == "__main__":
    main() 

    
