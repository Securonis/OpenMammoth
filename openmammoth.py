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
        
        if not self.available_interfaces:
            print(f"{Fore.RED}Warning: No network interfaces found!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please check and configure your network interfaces.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Recommended steps:{Style.RESET_ALL}")
            print("1. Check your network connection")
            print("2. Configure your network interfaces")
            print("3. Restart the program")
            input("\nPress Enter to return to main menu...")

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
                    logging.warning(f"Attack detected from {ip_src}")
                
                self.stats['total_packets'] += 1
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
        if IP in packet:
            ip_src = packet[IP].src
            
            # Check for packet rate attacks
            if self.check_packet_rate(ip_src):
                return True
                
            # Check for SYN flood
            if TCP in packet and packet[TCP].flags == 0x02:
                if self.check_syn_flood(ip_src):
                    self.stats['syn_floods'] += 1
                    logging.warning(f"SYN flood detected from {ip_src}")
                    return True
                    
            # Check for UDP flood
            if UDP in packet:
                if self.check_udp_flood(ip_src):
                    self.stats['udp_floods'] += 1
                    logging.warning(f"UDP flood detected from {ip_src}")
                    return True
                    
            # Check for ICMP flood
            if ICMP in packet:
                if self.check_icmp_flood(ip_src):
                    self.stats['icmp_floods'] += 1
                    logging.warning(f"ICMP flood detected from {ip_src}")
                    return True
                    
            # Check for port scan
            if self.check_port_scan(ip_src):
                self.stats['port_scans'] += 1
                logging.warning(f"Port scan detected from {ip_src}")
                return True
                
            # Check for DNS amplification
            if self.check_dns_amplification(packet):
                self.stats['dns_amplification'] += 1
                logging.warning(f"DNS amplification detected from {ip_src}")
                return True
                
            # Check for fragment attacks
            if self.check_fragment_attack(packet):
                self.stats['fragment_attacks'] += 1
                logging.warning(f"Fragment attack detected from {ip_src}")
                return True
                
            # Check for malformed packets
            if self.check_malformed_packet(packet):
                self.stats['malformed_packets'] += 1
                logging.warning(f"Malformed packet detected from {ip_src}")
                return True
                
            # Check for IP spoofing
            if self.check_ip_spoofing(packet):
                self.stats['spoofed_ips'] += 1
                logging.warning(f"Possible IP spoofing detected from {ip_src}")
                return True
                
            # Gelişmiş koruma etkinse ek kontroller yap
            if self.advanced_protection:
                # TTL analizi
                if self.check_ttl_anomalies(packet):
                    logging.warning(f"TTL anomaly detected from {ip_src}")
                    return True
                
                # TCP sequence prediction kontrolü
                if TCP in packet and self.check_tcp_sequence_prediction(packet):
                    logging.warning(f"TCP sequence prediction attack detected from {ip_src}")
                    return True
                
                # Null scan kontrolü
                if TCP in packet and packet[TCP].flags == 0:
                    logging.warning(f"Null scan detected from {ip_src}")
                    return True
                
                # FIN scan kontrolü
                if TCP in packet and packet[TCP].flags == 0x01:
                    logging.warning(f"FIN scan detected from {ip_src}")
                    return True
                
                # XMAS scan kontrolü
                if TCP in packet and packet[TCP].flags == 0x29:  # FIN, PSH, URG bayrakları
                    logging.warning(f"XMAS scan detected from {ip_src}")
                    return True
                
        return False

    def check_packet_rate(self, ip):
        if ip in self.packet_rates:
            rate = self.packet_rates[ip]['count']
            threshold = 1000 * self.protection_level
            return rate > threshold
        return False

    def check_syn_flood(self, ip):
        syn_count = sum(1 for conn in self.connection_tracker.values() 
                       if conn['count'] > 0 and time.time() - conn['timestamp'] < 1)
        threshold = 100 * self.protection_level
        return syn_count > threshold

    def check_udp_flood(self, ip):
        if ip in self.packet_rates:
            rate = self.packet_rates[ip]['count']
            threshold = 500 * self.protection_level
            return rate > threshold
        return False

    def check_icmp_flood(self, ip):
        if ip in self.packet_rates:
            rate = self.packet_rates[ip]['count']
            threshold = 200 * self.protection_level
            return rate > threshold
        return False

    def check_port_scan(self, ip):
        unique_ports = set()
        for conn in self.connection_tracker:
            if ip in conn:
                unique_ports.add(conn.split('-')[1])
        threshold = 50 * self.protection_level
        return len(unique_ports) > threshold

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
            # Normal TTL değerleri genellikle 32, 64, 128, 255 civarında olur
            # Çok düşük veya anormal TTL değerleri şüphelidir
            if ttl < 5 or ttl > 250:
                return True
        return False

    def check_tcp_sequence_prediction(self, packet):
        """TCP sequence tahmin saldırılarını kontrol et"""
        if TCP in packet:
            # Basit bir kontrol - gerçek bir uygulamada daha karmaşık olabilir
            seq = packet[TCP].seq
            if seq == 0 or seq == 1:
                return True
        return False

    def block_ip(self, ip, reason="Attack detected"):
        """Block an IP address"""
        # Don't try to block our own IPs
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
            if not self.select_interface():
                return False

        if not self.is_running:
            try:
                # If auto updates are enabled and it's time to check for updates
                if self.auto_update and time.time() - self.last_update_check > self.update_interval:
                    print(f"{Fore.YELLOW}Checking for updates...{Style.RESET_ALL}")
                    self.check_for_updates()
                
                # check for interface
                if not any(iface['name'] == self.interface and iface['status'] == 'UP' 
                          for iface in self.available_interfaces):
                    print(f"{Fore.RED}Error: Selected interface is not available!{Style.RESET_ALL}")
                    return False
                
                # Wait for commands to complete
                time.sleep(1)

                self.is_running = True
                # Save start time
                self.start_time = time.time()
                print(f"{Fore.GREEN}Starting protection on interface {self.interface}...{Style.RESET_ALL}")
                
                def packet_capture():
                    try:
                        sniff(iface=self.interface, prn=self.packet_handler, store=0, stop_filter=lambda p: not self.is_running)
                    except Exception as e:
                        logging.error(f"Error in packet capture: {str(e)}")
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
                
                self.capture_thread = threading.Thread(target=packet_capture)
                self.capture_thread.daemon = True
                self.capture_thread.start()
                
                self.cleanup_thread = threading.Thread(target=data_cleanup)
                self.cleanup_thread.daemon = True
                self.cleanup_thread.start()
                
                self.update_thread = threading.Thread(target=auto_updater)
                self.update_thread.daemon = True
                self.update_thread.start()
                
                logging.info(f"Protection started on interface {self.interface}")
                return True
            except Exception as e:
                print(f"{Fore.RED}Error starting protection: {str(e)}{Style.RESET_ALL}")
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
            print(f"{Fore.YELLOW}3. Settings{Style.RESET_ALL}")
            print(f"{Fore.BLUE}4. View Statistics{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}5. View Blocked IPs{Style.RESET_ALL}")
            print(f"{Fore.CYAN}6. Advanced Options{Style.RESET_ALL}")
            print(f"{Fore.WHITE}7. Help{Style.RESET_ALL}")
            print(f"{Fore.CYAN}8. About{Style.RESET_ALL}")
            print(f"{Fore.RED}9. Exit{Style.RESET_ALL}")
            
            choice = input("\nEnter your choice (1-9): ")
            
            if choice == "1":
                self.start_protection()
            elif choice == "2":
                self.stop_protection()
            elif choice == "3":
                self.settings_menu()
            elif choice == "4":
                self.view_statistics()
            elif choice == "5":
                self.view_blocked_ips()
            elif choice == "6":
                self.advanced_options()
            elif choice == "7":
                self.show_help()
            elif choice == "8":
                self.show_about()
            elif choice == "9":
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
            print("7. Back to Main Menu")
            
            choice = input("\nEnter your choice (1-7): ")
            
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
        print(f"\n{Fore.CYAN}=== Blocked IP Addresses ==={Style.RESET_ALL}")
        if not self.blocked_ips:
            print("No IPs are currently blocked.")
        else:
            for ip, info in self.blocked_ips.items():
                duration = time.time() - info['timestamp']
                print(f"IP: {ip}")
                print(f"Blocked for: {duration:.2f} seconds")
                print(f"Reason: {info['reason']}")
                print("-" * 40)

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
        try:
            log_path = os.path.join(self.config_dir, 'openmammoth.log')
            with open(log_path, 'r') as f:
                print(f"\n{Fore.CYAN}=== Recent Logs ==={Style.RESET_ALL}")
                for line in f.readlines()[-20:]:  # Show last 20 lines
                    print(line.strip())
        except FileNotFoundError:
            print(f"{Fore.RED}No log file found.{Style.RESET_ALL}")

    def export_statistics(self):
        filename = f"stats_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.stats, f, indent=4)
        print(f"\n{Fore.GREEN}Statistics exported to {filename}{Style.RESET_ALL}")

    def clear_blocked_ips(self):
        """Clear blocked IPs"""
        ips_to_unblock = [ip for ip in self.blocked_ips if ip not in self.blacklist]
        if not ips_to_unblock:
            print(f"{Fore.YELLOW}No temporary blocked IPs to clear.{Style.RESET_ALL}")
            return
            
        try:
            for ip in ips_to_unblock:
                try:
                    subprocess.run(
                        ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                        capture_output=True, text=True, check=True
                    )
                    del self.blocked_ips[ip]
                except Exception as e:
                    logging.error(f"Error removing iptables rule for {ip}: {str(e)}")
            
            print(f"\n{Fore.GREEN}All temporary blocked IPs have been cleared.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Note: Blacklisted IPs remain blocked.{Style.RESET_ALL}")
        except Exception as e:
            logging.error(f"Error clearing blocked IPs: {str(e)}")
            print(f"{Fore.RED}Error clearing blocked IPs: {str(e)}{Style.RESET_ALL}")

    def manage_whitelist(self):
        """Manage whitelist"""
        while True:
            print(f"\n{Fore.CYAN}=== Whitelist Management ==={Style.RESET_ALL}")
            print("1. View Whitelist")
            print("2. Add IP to Whitelist")
            print("3. Remove IP from Whitelist")
            print("4. Back to Advanced Options")
            
            choice = input("\nEnter your choice (1-4): ")
            
            if choice == "1":
                self.view_whitelist()
            elif choice == "2":
                ip = input("Enter IP address to whitelist: ")
                if self.add_to_whitelist(ip):
                    print(f"{Fore.GREEN}IP {ip} added to whitelist.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Failed to add IP to whitelist.{Style.RESET_ALL}")
            elif choice == "3":
                self.view_whitelist()
                if self.whitelist:
                    ip_idx = input("Enter index of IP to remove (or 'q' to cancel): ")
                    if ip_idx.lower() != 'q':
                        try:
                            idx = int(ip_idx) - 1
                            if 0 <= idx < len(self.whitelist):
                                ip = self.whitelist.pop(idx)
                                self.save_ip_lists()
                                print(f"{Fore.GREEN}IP {ip} removed from whitelist.{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.RED}Invalid index.{Style.RESET_ALL}")
                        except ValueError:
                            print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")
            elif choice == "4":
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    def view_whitelist(self):
        """View whitelisted IP addresses"""
        print(f"\n{Fore.CYAN}=== Whitelisted IP Addresses ==={Style.RESET_ALL}")
        if not self.whitelist:
            print("No IPs are whitelisted.")
        else:
            for idx, ip in enumerate(self.whitelist, 1):
                print(f"{idx}. {ip}")

    def manage_blacklist(self):
        """Manage blacklist"""
        while True:
            print(f"\n{Fore.CYAN}=== Blacklist Management ==={Style.RESET_ALL}")
            print("1. View Blacklist")
            print("2. Add IP to Blacklist")
            print("3. Remove IP from Blacklist")
            print("4. Back to Advanced Options")
            
            choice = input("\nEnter your choice (1-4): ")
            
            if choice == "1":
                self.view_blacklist()
            elif choice == "2":
                ip = input("Enter IP address to blacklist: ")
                if self.add_to_blacklist(ip):
                    print(f"{Fore.GREEN}IP {ip} added to blacklist.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Failed to add IP to blacklist.{Style.RESET_ALL}")
            elif choice == "3":
                self.view_blacklist()
                if self.blacklist:
                    ip_idx = input("Enter index of IP to remove (or 'q' to cancel): ")
                    if ip_idx.lower() != 'q':
                        try:
                            idx = int(ip_idx) - 1
                            if 0 <= idx < len(self.blacklist):
                                ip = self.blacklist.pop(idx)
                                if ip in self.blocked_ips:
                                    try:
                                        subprocess.run(
                                            ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                                            capture_output=True, text=True, check=True
                                        )
                                        del self.blocked_ips[ip]
                                    except Exception as e:
                                        logging.error(f"Error removing rule for {ip}: {str(e)}")
                                self.save_ip_lists()
                                print(f"{Fore.GREEN}IP {ip} removed from blacklist.{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.RED}Invalid index.{Style.RESET_ALL}")
                        except ValueError:
                            print(f"{Fore.RED}Please enter a valid number.{Style.RESET_ALL}")
            elif choice == "4":
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    def view_blacklist(self):
        """View blacklisted IP addresses"""
        print(f"\n{Fore.CYAN}=== Blacklisted IP Addresses ==={Style.RESET_ALL}")
        if not self.blacklist:
            print("No IPs are blacklisted.")
        else:
            for idx, ip in enumerate(self.blacklist, 1):
                print(f"{idx}. {ip}")

    def firewall_settings(self):
        """Manage firewall settings"""
        while True:
            print(f"\n{Fore.CYAN}=== Firewall Settings ==={Style.RESET_ALL}")
            print("1. View Current Firewall Rules")
            print("2. Reset All Firewall Rules")
            print("3. Apply Basic Protection Rules")
            print("4. Back to Advanced Options")
            
            choice = input("\nEnter your choice (1-4): ")
            
            if choice == "1":
                self.view_firewall_rules()
            elif choice == "2":
                confirmed = input(f"{Fore.RED}Warning: This will reset all iptables rules. Continue? (y/n): {Style.RESET_ALL}")
                if confirmed.lower() == 'y':
                    self.reset_firewall_rules()
                    print(f"{Fore.GREEN}Firewall rules reset.{Style.RESET_ALL}")
            elif choice == "3":
                self.apply_basic_protection()
                print(f"{Fore.GREEN}Basic protection rules applied.{Style.RESET_ALL}")
            elif choice == "4":
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    def view_firewall_rules(self):
        """View current firewall rules"""
        try:
            result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True)
            print(f"\n{Fore.CYAN}=== Current Firewall Rules ==={Style.RESET_ALL}")
            print(result.stdout)
        except Exception as e:
            print(f"{Fore.RED}Error viewing firewall rules: {str(e)}{Style.RESET_ALL}")

    def reset_firewall_rules(self):
        """Reset all firewall rules"""
        try:
            subprocess.run(['iptables', '-F'], check=True)
            subprocess.run(['iptables', '-X'], check=True)
            subprocess.run(['iptables', '-t', 'nat', '-F'], check=True)
            subprocess.run(['iptables', '-t', 'nat', '-X'], check=True)
            subprocess.run(['iptables', '-t', 'mangle', '-F'], check=True)
            subprocess.run(['iptables', '-t', 'mangle', '-X'], check=True)
            subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
            
            # Update blocked_ips after rules are cleared
            self.blocked_ips.clear()
            
            logging.info("Firewall rules reset")
        except Exception as e:
            logging.error(f"Error resetting firewall rules: {str(e)}")

    def apply_basic_protection(self):
        """Apply basic protection rules"""
        try:
            # First clean up existing rules
            self.reset_firewall_rules()
            
            # Set default policies
            subprocess.run(['iptables', '-P', 'INPUT', 'DROP'], check=True)
            subprocess.run(['iptables', '-P', 'FORWARD', 'DROP'], check=True)
            subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
            
            # Allow loopback traffic
            subprocess.run(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=True)
            
            # Allow established connections
            subprocess.run(['iptables', '-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], check=True)
            
            # Allow SSH connections (can be changed as needed)
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'], check=True)
            
            # Allow ping requests (optional)
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'icmp', '--icmp-type', 'echo-request', '-j', 'ACCEPT'], check=True)
            
            # Allow DNS traffic
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'udp', '--dport', '53', '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '53', '-j', 'ACCEPT'], check=True)
            
            # Allow HTTP and HTTPS traffic
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '80', '-j', 'ACCEPT'], check=True)
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'], check=True)
            
            # Block IPs in the blacklist
            for ip in self.blacklist:
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                self.blocked_ips[ip] = {
                    'timestamp': time.time(),
                    'reason': 'Blacklisted'
                }
            
            logging.info("Basic protection rules applied")
        except Exception as e:
            logging.error(f"Error applying basic protection rules: {str(e)}")

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
        print(f"{Fore.YELLOW}Version: 1.0.0{Style.RESET_ALL}")
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
        print(f"\n{Fore.CYAN}GitHub: https://github.com/root0emir{Style.RESET_ALL}")
        input("\nPress Enter to return to main menu...")

    def get_available_interfaces(self):
        """Get available network interfaces"""
        interfaces = []
        try:
            for iface in get_if_list():
                try:
                    # Get interface ip
                    ip = get_if_addr(iface)
                    if ip:
                        # get interface mac
                        mac = get_if_hwaddr(iface)
                        interfaces.append({
                            'name': iface,
                            'ip': ip,
                            'mac': mac,
                            'status': 'UP' if get_if_raw_hwaddr(iface) else 'DOWN'
                        })
                except:
                    continue
        except:
            pass
        return interfaces

    def display_interfaces(self):
        """Display network interfaces"""
        print(f"\n{Fore.CYAN}=== Available Network Interfaces ==={Style.RESET_ALL}")
        if not self.available_interfaces:
            print(f"{Fore.RED}Warning: No network interfaces found!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please check and configure your network interfaces.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Recommended steps:{Style.RESET_ALL}")
            print("1. Check your network connection")
            print("2. Configure your network interfaces")
            print("3. Restart the program")
            input("\nPress Enter to return to main menu...")
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
            print(f"{Fore.YELLOW}Please check and configure your network interfaces.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Recommended steps:{Style.RESET_ALL}")
            print("1. Check your network connection")
            print("2. Configure your network interfaces")
            print("3. Restart the program")
            input("\nPress Enter to return to main menu...")
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
        """Tehdit istihbaratı veritabanını yükle"""
        try:
            intel_path = os.path.join(self.config_dir, 'threat_intel.json')
            if os.path.exists(intel_path):
                with open(intel_path, 'r') as f:
                    self.threat_intel_db = json.load(f)
                    logging.info(f"Loaded {len(self.threat_intel_db)} threat intelligence entries")
            else:
                # İlk kez çalıştırılıyorsa, boş bir veritabanı oluştur
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

def main():
    if os.geteuid() != 0:
        print(f"{Fore.RED}Error: This program must be run as root.{Style.RESET_ALL}")
        sys.exit(1)
    
    tool = OpenMammoth()
    tool.display_menu()

if __name__ == "__main__":
    main() 
