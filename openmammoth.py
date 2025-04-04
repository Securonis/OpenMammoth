#!/usr/bin/env python3
import os
import sys
import json
import time
import threading
import logging
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
            "spoofed_ips": 0
        }
        self.connection_tracker = {}
        self.packet_rates = {}
        self.is_running = False
        self.config_dir = "/etc/securonis"
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
        self.load_config()
        self.setup_logging()
        self.available_interfaces = self.get_available_interfaces()
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
        except FileNotFoundError:
            self.save_config()

    def save_config(self):
        config = {
            'protection_level': self.protection_level,
            'advanced_protection': self.advanced_protection,
            'debug_mode': self.debug_mode,
            'interface': self.interface
        }
        config_path = os.path.join(self.config_dir, 'config.json')
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)

    def packet_handler(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Update connection tracking
            self.update_connection_tracker(ip_src, ip_dst)
            
            # Update packet rates
            self.update_packet_rates(ip_src)
            
            # Check for various types of attacks
            if self.detect_attacks(packet):
                self.block_ip(ip_src)
                self.stats['blocked_packets'] += 1
                self.stats['attacks_detected'] += 1
                logging.warning(f"Attack detected from {ip_src}")
            
            self.stats['total_packets'] += 1

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
                    return True
                    
            # Check for UDP flood
            if UDP in packet:
                if self.check_udp_flood(ip_src):
                    self.stats['udp_floods'] += 1
                    return True
                    
            # Check for ICMP flood
            if ICMP in packet:
                if self.check_icmp_flood(ip_src):
                    self.stats['icmp_floods'] += 1
                    return True
                    
            # Check for port scan
            if self.check_port_scan(ip_src):
                self.stats['port_scans'] += 1
                return True
                
            # Check for DNS amplification
            if self.check_dns_amplification(packet):
                self.stats['dns_amplification'] += 1
                return True
                
            # Check for fragment attacks
            if self.check_fragment_attack(packet):
                self.stats['fragment_attacks'] += 1
                return True
                
            # Check for malformed packets
            if self.check_malformed_packet(packet):
                self.stats['malformed_packets'] += 1
                return True
                
            # Check for IP spoofing
            if self.check_ip_spoofing(packet):
                self.stats['spoofed_ips'] += 1
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

    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            self.blocked_ips[ip] = {
                'timestamp': time.time(),
                'reason': 'Attack detected'
            }
            os.system(f'iptables -A INPUT -s {ip} -j DROP')
            logging.info(f"Blocked IP: {ip}")

    def start_protection(self):
        if not self.interface:
            print(f"{Fore.RED}Error: No network interface selected!{Style.RESET_ALL}")
            if not self.select_interface():
                return False

        if not self.is_running:
            try:
                # check for interface
                if not any(iface['name'] == self.interface and iface['status'] == 'UP' 
                          for iface in self.available_interfaces):
                    print(f"{Fore.RED}Error: Selected interface is not available!{Style.RESET_ALL}")
                    return False

                self.is_running = True
                print(f"{Fore.GREEN}Starting protection on interface {self.interface}...{Style.RESET_ALL}")
                
                def packet_capture():
                    sniff(iface=self.interface, prn=self.packet_handler, store=0)
                
                capture_thread = threading.Thread(target=packet_capture)
                capture_thread.daemon = True
                capture_thread.start()
                
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
            # Cleanup iptables rules
            for ip in self.blocked_ips:
                os.system(f'iptables -D INPUT -s {ip} -j DROP')
            self.blocked_ips.clear()
            logging.info("Protection stopped")
            return True
        return False

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
            print("5. Back to Main Menu")
            
            choice = input("\nEnter your choice (1-5): ")
            
            if choice == "1":
                level = input("Enter protection level (1-4): ")
                if level.isdigit() and 1 <= int(level) <= 4:
                    self.protection_level = int(level)
                    self.save_config()
            elif choice == "2":
                self.advanced_protection = not self.advanced_protection
                self.save_config()
            elif choice == "3":
                self.debug_mode = not self.debug_mode
                self.setup_logging()
                self.save_config()
            elif choice == "4":
                if self.select_interface():
                    self.save_config()
            elif choice == "5":
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    def view_statistics(self):
        print(f"\n{Fore.CYAN}=== Protection Statistics ==={Style.RESET_ALL}")
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
            print("4. Test Protection")
            print("5. Back to Main Menu")
            
            choice = input("\nEnter your choice (1-5): ")
            
            if choice == "1":
                self.view_logs()
            elif choice == "2":
                self.export_statistics()
            elif choice == "3":
                self.clear_blocked_ips()
            elif choice == "4":
                self.test_protection()
            elif choice == "5":
                break
            else:
                print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    def view_logs(self):
        try:
            with open('openmammoth.log', 'r') as f:
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
        for ip in list(self.blocked_ips.keys()):
            os.system(f'iptables -D INPUT -s {ip} -j DROP')
        self.blocked_ips.clear()
        print(f"\n{Fore.GREEN}All blocked IPs have been cleared.{Style.RESET_ALL}")

    def test_protection(self):
        print(f"\n{Fore.CYAN}=== Protection Test ==={Style.RESET_ALL}")
        print("1. Test Port Scan Detection")
        print("2. Test SYN Flood Detection")
        print("3. Test UDP Flood Detection")
        print("4. Test ICMP Flood Detection")
        print("5. Test DNS Amplification")
        print("6. Test Fragment Attack")
        print("7. Test Malformed Packet")
        print("8. Test IP Spoofing")
        print("9. Back to Advanced Options")
        
        choice = input("\nEnter your choice (1-9): ")
        
        if choice == "1":
            self.simulate_port_scan()
        elif choice == "2":
            self.simulate_syn_flood()
        elif choice == "3":
            self.simulate_udp_flood()
        elif choice == "4":
            self.simulate_icmp_flood()
        elif choice == "5":
            self.simulate_dns_amplification()
        elif choice == "6":
            self.simulate_fragment_attack()
        elif choice == "7":
            self.simulate_malformed_packet()
        elif choice == "8":
            self.simulate_ip_spoofing()
        elif choice != "9":
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    def simulate_port_scan(self):
        print(f"{Fore.YELLOW}Simulating port scan...{Style.RESET_ALL}")
        try:
            target_ip = input("Enter target IP (default: 127.0.0.1): ") or "127.0.0.1"
            start_port = int(input("Enter start port (default: 1): ") or "1")
            end_port = int(input("Enter end port (default: 100): ") or "100")
            
            print(f"Scanning ports {start_port} to {end_port} on {target_ip}...")
            
            for port in range(start_port, end_port + 1):
                packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
                send(packet, verbose=0)
                time.sleep(0.1)  # Slow down the scan
            
            print(f"{Fore.GREEN}Port scan simulation completed.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error during port scan simulation: {str(e)}{Style.RESET_ALL}")

    def simulate_syn_flood(self):
        print(f"{Fore.YELLOW}Simulating SYN flood...{Style.RESET_ALL}")
        try:
            target_ip = input("Enter target IP (default: 127.0.0.1): ") or "127.0.0.1"
            target_port = int(input("Enter target port (default: 80): ") or "80")
            duration = int(input("Enter duration in seconds (default: 5): ") or "5")
            
            print(f"Starting SYN flood attack on {target_ip}:{target_port} for {duration} seconds...")
            
            end_time = time.time() + duration
            while time.time() < end_time:
                packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
                send(packet, verbose=0)
                time.sleep(0.001)  # Send 1000 packets per second
            
            print(f"{Fore.GREEN}SYN flood simulation completed.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error during SYN flood simulation: {str(e)}{Style.RESET_ALL}")

    def simulate_udp_flood(self):
        print(f"{Fore.YELLOW}Simulating UDP flood...{Style.RESET_ALL}")
        try:
            target_ip = input("Enter target IP (default: 127.0.0.1): ") or "127.0.0.1"
            target_port = int(input("Enter target port (default: 53): ") or "53")
            duration = int(input("Enter duration in seconds (default: 5): ") or "5")
            
            print(f"Starting UDP flood attack on {target_ip}:{target_port} for {duration} seconds...")
            
            end_time = time.time() + duration
            while time.time() < end_time:
                packet = IP(dst=target_ip)/UDP(dport=target_port)/Raw(load="X"*1000)
                send(packet, verbose=0)
                time.sleep(0.001)  # Send 1000 packets per second
            
            print(f"{Fore.GREEN}UDP flood simulation completed.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error during UDP flood simulation: {str(e)}{Style.RESET_ALL}")

    def simulate_icmp_flood(self):
        print(f"{Fore.YELLOW}Simulating ICMP flood...{Style.RESET_ALL}")
        try:
            target_ip = input("Enter target IP (default: 127.0.0.1): ") or "127.0.0.1"
            duration = int(input("Enter duration in seconds (default: 5): ") or "5")
            
            print(f"Starting ICMP flood attack on {target_ip} for {duration} seconds...")
            
            end_time = time.time() + duration
            while time.time() < end_time:
                packet = IP(dst=target_ip)/ICMP()
                send(packet, verbose=0)
                time.sleep(0.001)  # Send 1000 packets per second
            
            print(f"{Fore.GREEN}ICMP flood simulation completed.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error during ICMP flood simulation: {str(e)}{Style.RESET_ALL}")

    def simulate_dns_amplification(self):
        print(f"{Fore.YELLOW}Simulating DNS amplification...{Style.RESET_ALL}")
        try:
            target_ip = input("Enter target IP (default: 127.0.0.1): ") or "127.0.0.1"
            dns_server = input("Enter DNS server IP (default: 8.8.8.8): ") or "8.8.8.8"
            duration = int(input("Enter duration in seconds (default: 5): ") or "5")
            
            print(f"Starting DNS amplification attack on {target_ip} using {dns_server} for {duration} seconds...")
            
            # Create a large DNS query
            dns_query = IP(dst=dns_server, src=target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com", qtype="ANY"))
            
            end_time = time.time() + duration
            while time.time() < end_time:
                send(dns_query, verbose=0)
                time.sleep(0.1)  # Send 10 queries per second
            
            print(f"{Fore.GREEN}DNS amplification simulation completed.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error during DNS amplification simulation: {str(e)}{Style.RESET_ALL}")

    def simulate_fragment_attack(self):
        print(f"{Fore.YELLOW}Simulating fragment attack...{Style.RESET_ALL}")
        try:
            target_ip = input("Enter target IP (default: 127.0.0.1): ") or "127.0.0.1"
            duration = int(input("Enter duration in seconds (default: 5): ") or "5")
            
            print(f"Starting fragment attack on {target_ip} for {duration} seconds...")
            
            # Create a large packet that will be fragmented
            payload = "X" * 2000  # Large payload to force fragmentation
            
            end_time = time.time() + duration
            while time.time() < end_time:
                packet = IP(dst=target_ip, flags="MF", frag=0)/UDP(dport=53)/Raw(load=payload)
                send(packet, verbose=0)
                time.sleep(0.1)  # Send 10 packets per second
            
            print(f"{Fore.GREEN}Fragment attack simulation completed.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error during fragment attack simulation: {str(e)}{Style.RESET_ALL}")

    def simulate_malformed_packet(self):
        print(f"{Fore.YELLOW}Simulating malformed packet...{Style.RESET_ALL}")
        try:
            target_ip = input("Enter target IP (default: 127.0.0.1): ") or "127.0.0.1"
            duration = int(input("Enter duration in seconds (default: 5): ") or "5")
            
            print(f"Starting malformed packet attack on {target_ip} for {duration} seconds...")
            
            end_time = time.time() + duration
            while time.time() < end_time:
                # Create a packet with invalid IP header length
                packet = IP(dst=target_ip, ihl=6)/TCP(dport=80, flags="S")
                send(packet, verbose=0)
                time.sleep(0.1)  # Send 10 packets per second
            
            print(f"{Fore.GREEN}Malformed packet simulation completed.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error during malformed packet simulation: {str(e)}{Style.RESET_ALL}")

    def simulate_ip_spoofing(self):
        print(f"{Fore.YELLOW}Simulating IP spoofing...{Style.RESET_ALL}")
        try:
            target_ip = input("Enter target IP (default: 127.0.0.1): ") or "127.0.0.1"
            spoofed_ip = input("Enter spoofed IP (default: 1.1.1.1): ") or "1.1.1.1"
            duration = int(input("Enter duration in seconds (default: 5): ") or "5")
            
            print(f"Starting IP spoofing attack on {target_ip} with spoofed IP {spoofed_ip} for {duration} seconds...")
            
            end_time = time.time() + duration
            while time.time() < end_time:
                packet = IP(src=spoofed_ip, dst=target_ip)/TCP(dport=80, flags="S")
                send(packet, verbose=0)
                time.sleep(0.1)  # Send 10 packets per second
            
            print(f"{Fore.GREEN}IP spoofing simulation completed.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error during IP spoofing simulation: {str(e)}{Style.RESET_ALL}")

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
        print("\nProtection Levels:")
        print("1. Basic - Minimal protection, low resource usage")
        print("2. Standard - Balanced protection")
        print("3. Enhanced - Strong protection")
        print("4. Extreme - Maximum protection")
        print("\nFor more information, visit the GitHub repository.")

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
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Attack simulation")
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
        """Show Interfaces"""
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
        """Showing Interfaces"""
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
        """Chosing interface"""
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

def main():
    if os.geteuid() != 0:
        print(f"{Fore.RED}Error: This program must be run as root.{Style.RESET_ALL}")
        sys.exit(1)
    
    tool = OpenMammoth()
    tool.display_menu()

if __name__ == "__main__":
    main() 
