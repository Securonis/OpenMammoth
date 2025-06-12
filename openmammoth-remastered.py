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
import random
import math  # For entropy calculation in DNS tunneling detection
import ipapi  # For IP geolocation and VPN detection
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import init, Fore, Style
from threading import Lock, RLock
from queue import Queue, Empty
from collections import OrderedDict
from contextlib import nullcontext
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

# Initialize colorama
init()

class OpenMammoth:
    def __init__(self):
        # Initialize attack tracking dictionaries
        self.syn_tracker = {}        # Track SYN packets for SYN flood detection
        self.port_scan_tracker = {}  # Track connection attempts for port scan detection
        self.udp_flood_tracker = {}  # Track UDP packets for UDP flood detection
        self.icmp_flood_tracker = {} # Track ICMP packets for ICMP flood detection
        self.frag_tracker = {}       # Track fragmented packets for fragmentation attacks
        self.arp_tracker = {}        # Track ARP packets for ARP spoofing detection
        self.ttl_tracker = {}        # Track TTL values for TTL-based attacks
        self.dns_tracker = {}        # Track DNS responses for amplification attacks
        self.seq_tracker = {}        # Track TCP sequence numbers for TCP sequence prediction
        self.http_tracker = {}       # Track HTTP requests for HTTP flood detection
        self.rst_tracker = {}        # Track RST flags for RST flood detection
        self.slow_tracker = {}       # Track slow connections for low-and-slow attack detection
        self.dns_tunnel_tracker = {} # Track DNS queries for tunneling detection
        self.vpn_proxy_tracker = {} # Track VPN/Proxy connections
        self.websocket_tracker = {} # Track WebSocket connections for WebSocket flood detection
        
        # Attack thresholds and timeouts - optimized for accuracy and minimal missed detections
        self.syn_flood_threshold = 10       # Number of SYNs before considering it a flood (was 50)
        self.syn_flood_rate_threshold = 3   # SYN packets per second rate threshold for proactive detection
        self.syn_flood_timeout = 60         # Time window for SYN flood detection (seconds) (was 5)
        self.port_scan_threshold = 5        # Number of ports before considering it a scan (was 20)
        self.port_scan_timeout = 60         # Time window for port scan detection (seconds) (was 10)
        self.port_scan_pattern_weight = 2   # Multiplier for sequential port scanning patterns
        self.udp_flood_threshold = 15       # Number of UDP packets before considering it a flood
        self.udp_flood_timeout = 30         # Time window for UDP flood detection (seconds)
        self.icmp_flood_threshold = 10      # Number of ICMP packets before considering it a flood
        self.icmp_flood_timeout = 30        # Time window for ICMP flood detection (seconds)
        self.frag_threshold = 8             # Number of fragmented packets from same source before alerting
        self.frag_timeout = 30              # Time window for fragment attack detection (seconds)
        self.arp_threshold = 3              # Number of ARP changes for same IP before considering it spoofing
        self.arp_timeout = 120              # Time window for ARP spoofing detection (seconds)
        self.ttl_anomaly_threshold = 5      # Number of packets with abnormal TTL before alerting
        self.dns_amp_threshold = 12         # Number of large DNS responses before considering it amplification
        self.dns_amp_size = 512             # Size in bytes to consider a DNS response potentially part of amplification
        self.dns_amp_timeout = 30           # Time window for DNS amplification detection (seconds)
        self.seq_pred_sample_size = 8       # Number of TCP packets to sample for sequence prediction analysis
        self.seq_pred_timeout = 60          # Time window for TCP sequence prediction detection (seconds)
        
        # New attack thresholds - HTTP, RST, and slow attacks
        self.http_flood_threshold = 30      # Number of HTTP requests before considering it a flood
        self.http_flood_timeout = 10        # Time window for HTTP flood detection (seconds)
        self.http_path_threshold = 5        # Number of different paths/endpoints to consider suspicious
        self.rst_flood_threshold = 15       # Number of RST packets before considering it a flood
        self.rst_flood_timeout = 5          # Time window for RST flood detection (seconds)
        self.slow_conn_threshold = 6        # Number of slow connections before considering it an attack
        self.slow_conn_timeout = 120        # Time window for slow connection detection (seconds)
        self.slow_conn_duration = 30        # Duration in seconds that a connection must stay open to be considered slow
        
        # DNS tunneling detection configuration
        self.dns_tunnel_enabled = True      # Whether DNS tunneling detection is enabled
        self.dns_tunnel_threshold = 20      # Number of suspicious DNS queries before alerting
        self.dns_subdomain_threshold = 5    # Max subdomain depth before considering suspicious
        self.dns_length_threshold = 40      # Length of hostname part that's suspicious
        self.dns_entropy_threshold = 3.5    # Shannon entropy threshold for random-looking domains
        self.dns_tunnel_timeout = 60        # Time window for DNS tunnel detection (seconds)
        
        # VPN/Proxy detection configuration
        self.vpn_proxy_enabled = True       # Whether VPN/Proxy detection is enabled
        self.vpn_proxy_threshold = 5        # Number of suspicious connections before alerting
        self.vpn_proxy_timeout = 300        # Time window for VPN/Proxy detection (seconds)
        self.vpn_proxy_check_interval = 60  # How often to check cached IPs (seconds)
        self.vpn_proxy_cache = {}           # Cache for VPN/Proxy results to limit API calls
        self.vpn_proxy_cache_timeout = 3600 # How long to cache VPN/Proxy results (seconds)
        
        # WebSocket attack detection configuration
        self.websocket_enabled = True        # Whether WebSocket attack detection is enabled
        self.websocket_threshold = 30        # Number of WebSocket connections before considering it a flood
        self.websocket_timeout = 60          # Time window for WebSocket flood detection (seconds)
        self.http2_enabled = True            # Whether HTTP/2 attack detection is enabled
        self.http2_threshold = 40            # Number of HTTP/2 frames before considering it a flood
        self.http2_timeout = 60              # Time window for HTTP/2 flood detection (seconds)
        
        # Honeypot configuration
        self.honeypot_enabled = False      # Whether honeypot detection is enabled
        self.honeypot_ports = [22, 23, 445, 1433, 3306, 3389, 5900]  # Common attack targets
        self.honeypot_tracker = {}         # Track connection attempts to honeypot ports
        self.honeypot_threshold = 3        # Number of attempts before considering malicious
        self.honeypot_detection_window = 60  # Time window for honeypot detection (seconds)
        self.flood_alerting_interval = 60   # Minimum time between alerts (seconds)
        self.last_alert_time = {}           # Track when alerts were last sent
        
        # Tracking locks for thread safety
        self.syn_lock = Lock()              # Lock for SYN tracker
        self.port_scan_lock = Lock()        # Lock for port scan tracker
        self.udp_lock = Lock()              # Lock for UDP tracker
        self.icmp_lock = Lock()             # Lock for ICMP tracker
        self.frag_lock = Lock()             # Lock for fragmentation tracker
        self.arp_lock = Lock()              # Lock for ARP tracker
        self.ttl_lock = Lock()              # Lock for TTL tracker
        self.dns_lock = Lock()              # Lock for DNS tracker
        self.seq_lock = Lock()              # Lock for TCP sequence tracker
        self.http_lock = Lock()             # Lock for HTTP tracker
        self.rst_lock = Lock()              # Lock for RST tracker
        self.slow_lock = Lock()             # Lock for slow connection tracker
        self.honeypot_lock = Lock()         # Lock for honeypot tracker
        self.dns_tunnel_lock = Lock()       # Lock for DNS tunneling tracker
        self.vpn_proxy_lock = Lock()       # Lock for VPN/Proxy tracker
        self.websocket_lock = Lock()      # Lock for WebSocket tracker
        
        # Colorama initialization
        init(autoreset=True)
        
        # Set up signal handlers for graceful shutdown
        self._setup_signal_handlers()
        
        # Basic configuration
        self.protection_level = 2
        self.advanced_protection = False
        self.debug_mode = False
        self.interface = None
        self.verbose = True               # Verbosity level for console output
        self.security_level = 2           # Security level for automatic blocking (1-4)
        
        # Thread synchronization locks to prevent race conditions
        self.stats_lock = RLock()          # For safely updating statistics
        self.connection_lock = RLock()     # For connection tracking updates
        self.packet_rates_lock = RLock()   # For packet rate updates
        self.tcp_flags_lock = RLock()      # For TCP flags tracking 
        self.block_list_lock = RLock()     # For IP block list modifications
        self.http_detect_lock = RLock()    # For HTTP attack detection
        self.defense_lock = RLock()        # For defense status modifications
        
        # Thread pool for parallel packet processing - improves throughput on multi-core systems
        self.thread_pool = ThreadPoolExecutor(max_workers=4)  # Adjust based on CPU cores
        
        # Core data structures with thread-safe access - now with OrderedDict for better performance
        self.blocked_ips = OrderedDict()
        
        # Defense status tracking dictionary - initialized with all defenses inactive
        self.defense_status = {
            'syn': False,      # SYN flood protection active
            'udp': False,      # UDP flood protection active
            'icmp': False,     # ICMP flood protection active
            'fragment': False, # Fragment attack protection active
            'dns': False       # DNS amplification protection active
        }
        
        # Runtime statistics - protected by stats_lock
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
            "reputation_blocks": 0,
            "dropped_packets": 0,
            "performance_issues": 0,
            "unusual_flags": 0   # Eksik istatistik eklendi
        }
        
        # Connection and packet tracking data structures
        self.connection_tracker = OrderedDict()
        self.packet_rates = OrderedDict()
        
        # Attack detection trackers
        self.syn_tracker = OrderedDict()         # For SYN flood detection
        self.udp_tracker = OrderedDict()         # For UDP flood detection 
        self.icmp_tracker = OrderedDict()        # For ICMP flood detection
        self.tcp_flags_tracker = OrderedDict()   # For unusual TCP flags
        self.port_scan_tracker = OrderedDict()   # For port scan detection
        self.seq_tracker = OrderedDict()         # For TCP sequence prediction attacks
        self.dns_tracker = OrderedDict()         # For DNS amplification attacks
        self.fragment_tracker = OrderedDict()    # For fragment attacks
        self.attack_sources = {}                 # For tracking persistent attackers
        
        # Execution state
        self.is_running = False
        self.capture_thread = None
        self.cleanup_thread = None
        self.update_thread = None
        
        # Performance monitoring and timing variables
        self.high_load = False
        self.last_performance_check = time.time()
        self.last_cleanup_time = time.time()
        self.last_defense_status_report = time.time()  # Initialize defense status report timer
        self.last_portscan_check = time.time()         # Initialize port scan check timer
        self.cleanup_interval = 300  # Clean up every 5 minutes
        
        # Paths and configuration
        self.config_dir = "/etc/securonis"
        
        # Threat intelligence and IP data
        self.threat_intel_db = {}
        self.ip_reputation_db = {}
        self.whitelist = []
        self.blacklist = []
        self.defense_ip_block_list = set()  # For storing IPs that triggered defense mechanisms
        
        # Update settings
        self.use_threat_intel = True
        self.auto_update = True
        self.last_update_check = 0
        self.update_interval = 86400  # 24 hours
        self.local_ips = []
        
        # Check system requirements and ensure root permissions
        if not self.check_root_permissions():
            print(f"{Fore.RED}Error: Root privileges required. Please run with sudo.{Style.RESET_ALL}")
            logging.error("OpenMammoth must be run with root privileges")
            sys.exit(1)
            
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
        # Submit packet to thread pool for parallel processing
        # This allows multiple packets to be processed simultaneously on multi-core systems
        if hasattr(self, 'thread_pool'):
            self.thread_pool.submit(self._process_packet, packet)
        else:
            # Fallback to direct processing if thread pool not available
            self._process_packet(packet)
    
    def _process_packet(self, packet):
        """Internal method to process a packet in a worker thread"""
        start_time = time.time()  # Start timing packet processing performance
        
        # Update packet counter first - this should happen for EVERY packet
        with self.stats_lock:
            self.stats['total_packets'] += 1
        
        # Skip non-IP packets
        if IP not in packet:
            return
            
        # Extract basic packet info for logging and analysis
        try:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
                
            # Skip packets to/from whitelisted IPs and local network management
            if ip_src in self.whitelist or ip_dst in self.whitelist:
                return
                
            # Skip internal communications between local IPs
            if ip_src in self.local_ips and ip_dst in self.local_ips:
                return
                
            # Resource management - limit dictionary sizes using thread-safe operations
            try:
                self._enforce_memory_limits()
            except Exception as mem_err:
                logging.error(f"Memory limit enforcement error: {str(mem_err)}")
            
            # Packet drop detection for high traffic environments
            try:
                if self.check_packet_drops(packet):
                    return
            except Exception as drop_err:
                logging.error(f"Error checking packet drops: {str(drop_err)}")
            
            # If process is overloaded, adjust priority
            if hasattr(self, 'high_load') and self.high_load:
                try:
                    self.prioritize_processing()
                except Exception as prio_err:
                    logging.error(f"Error adjusting process priority: {str(prio_err)}")
            
            # Filter whitelisted and local IPs
            try:
                if self.filter_ip(ip_src):
                    return
            except Exception as filter_err:
                logging.error(f"IP filtering error: {str(filter_err)}")
            
            # Check IP reputation and block if needed
            try:
                if self.check_ip_rep_and_block(ip_src):
                    return
            except Exception as rep_err:
                logging.error(f"Error checking IP reputation: {str(rep_err)}")
            
            # Update connection tracking and check rate limits
            try:
                if not self.track_connections_and_rates(ip_src, ip_dst):
                    # Packet dropped due to rate limiting
                    return
            except Exception as track_err:
                logging.error(f"Connection/rate tracking error: {str(track_err)}")
            
            # Application layer attack detection
            try:
                if self.handle_application_layer_attack(packet, ip_src):
                    return
            except Exception as app_err:
                logging.error(f"Application layer analysis error: {str(app_err)}")
                
            # Standard attack detection
            try:
                if self.handle_standard_attacks(packet, ip_src):
                    return
            except Exception as std_err:
                logging.error(f"Standard attack detection error: {str(std_err)}")
                
            # Performance monitoring and stats update
            try:
                self.monitor_performance(start_time)
            except Exception as perf_err:
                logging.error(f"Performance monitoring error: {str(perf_err)}")
                
        except Exception as e:
            # Critical error - top level exception handler ensures packet capture thread never dies
            logging.error(f"Critical error in packet handler: {str(e)}")
            print(f"{Fore.RED}[!] Critical error in packet handler: {str(e)}{Style.RESET_ALL}")
                    
            # Track errors
            with self.stats_lock:
                if not hasattr(self, 'error_count'):
                    self.error_count = 0
                self.error_count += 1
                    
                # Alert on many errors
                if self.error_count % 50 == 0:
                    print(f"{Fore.RED}[!!!] Multiple errors occurring: {self.error_count}. Check logs.{Style.RESET_ALL}")
                    logging.critical(f"Multiple packet handler errors: {self.error_count}. System may be unstable.")
                # End of packet processing

        except Exception as e:
            # Critical error - top level exception handler ensures packet capture thread never dies
            logging.error(f"Critical error in packet handler: {str(e)}")
            print(f"{Fore.RED}[!] Critical error in packet handler: {str(e)}{Style.RESET_ALL}")
            
            # Track errors
            if not hasattr(self, 'error_count'):
                self.error_count = 0
            self.error_count += 1
            
            # Alert on many errors
            if self.error_count % 50 == 0:
                print(f"{Fore.RED}[!!!] Multiple errors occurring: {self.error_count}. Check logs.{Style.RESET_ALL}")
                logging.critical(f"Multiple packet handler errors: {self.error_count}. System may be unstable.")

    def update_connection_tracker(self, ip_src, ip_dst):
        """Update connection tracking information in a thread-safe manner"""
        current_time = time.time()
        
        # Acquire lock to prevent race conditions during multi-threaded operation
        with self.connection_lock:
            if ip_src not in self.connection_tracker:
                self.connection_tracker[ip_src] = {
                    'connections': {},
                    'first_seen': current_time,
                    'last_seen': current_time
                }
            
            if ip_dst not in self.connection_tracker[ip_src]['connections']:
                self.connection_tracker[ip_src]['connections'][ip_dst] = {
                    'count': 1,
                    'first_seen': current_time,
                    'last_seen': current_time
                }
            else:
                self.connection_tracker[ip_src]['connections'][ip_dst]['count'] += 1
                self.connection_tracker[ip_src]['connections'][ip_dst]['last_seen'] = current_time
                
            self.connection_tracker[ip_src]['last_seen'] = current_time
            
            # Check if we need to enforce memory limits during high load
            connection_count = sum(len(src_data.get('connections', {})) 
                                 for src_data in self.connection_tracker.values())
            if connection_count > 50000:  # If tracking more than 50k connections
                self.high_load = True
                
    def update_packet_rates(self, ip):
        """Update packet rate tracking for a specific IP with rate limiting in a thread-safe manner"""
        current_time = time.time()
        packet_allowed = True
        
        # Use thread lock for safe updates in concurrent environments
        with self.packet_rates_lock:
            # Max packets per second for rate limiting (configurable)
            rate_limit = 500  # Default to 500 packets per second from a single IP
            
            if ip not in self.packet_rates:
                self.packet_rates[ip] = {
                    'count': 1,
                    'timestamp': current_time,
                    'dropped': 0  # Track dropped packets for high traffic monitoring
                }
            else:
                if current_time - self.packet_rates[ip]['timestamp'] > 1:
                    # Reset counters for new second but keep track of history
                    dropped = self.packet_rates[ip].get('dropped', 0)
                    self.packet_rates[ip] = {
                        'count': 1,
                        'timestamp': current_time,
                        'dropped': dropped
                    }
                else:
                    # Increment count within the current second
                    self.packet_rates[ip]['count'] += 1
                    
                    # Check for rate limiting
                    if self.packet_rates[ip]['count'] > rate_limit:
                        # This packet exceeds our rate limit
                        self.packet_rates[ip]['dropped'] = self.packet_rates[ip].get('dropped', 0) + 1
                        
                        # Update dropped packets stat with thread safety
                        with self.stats_lock:
                            if 'dropped_packets' not in self.stats:
                                self.stats['dropped_packets'] = 0
                            self.stats['dropped_packets'] += 1
                            
                        # Only log periodically to avoid flooding logs
                        if self.packet_rates[ip]['dropped'] % 100 == 0:
                            logging.warning(f"Rate limiting applied to {ip}: {self.packet_rates[ip]['dropped']} packets dropped")
                            print(f"{Fore.YELLOW}[!] High traffic from {ip}: {self.packet_rates[ip]['dropped']} packets rate limited{Style.RESET_ALL}")
                            
                        packet_allowed = False
        
        return packet_allowed
    def check_application_layer_attacks(self, packet):
        """Detect application layer attacks in HTTP/HTTPS traffic using thread-safe data structures
        Detects: SQLi, XSS, Path Traversal, Command Injection, File Inclusion"""
        if not TCP in packet:
            return False
            
        # Only inspect specific ports for efficiency: HTTP(S), common proxy ports
        http_ports = [80, 443, 8080, 8000, 8008, 8443, 3000, 8888]
        
        if not (packet.haslayer(TCP) and (packet[TCP].dport in http_ports or packet[TCP].sport in http_ports)):
            return False
            
        # Check if packet has payload data
        if not packet.haslayer(Raw):
            return False
            
        # Extract payload for analysis
        payload = str(packet[Raw].load)
        source_ip = packet[IP].src
        
        # Define attack signatures for various application attacks
        attack_signatures = {
            'sql_injection': [
                r"['\"][\s]*OR[\s]*['\"][\s]*=[\s]*['\"]\s*['\"]\s*--",  # OR '='--
                r"['\"][\s]*OR[\s]*\d+[\s]*=[\s]*\d+\s*--",  # OR 1=1--
                r"\bUNION[\s]+SELECT\b",  # UNION SELECT
                r"\bEXEC(?:UTE)?\s+(?:\w+\.)?\.?xp_",  # EXEC xp_
                r"\bINSERT\b.*\bINTO\b.*\bVALUES\b",  # INSERT INTO VALUES
                r"\bSELECT\b.*\bFROM\b.*\bWHERE\b"  # SELECT FROM WHERE
            ],
            'xss': [
                r"<[\s]*script[\s]*>.*?<[\s]*/[\s]*script[\s]*>",  # <script>...</script>
                r"javascript:[\s]*\(",  # javascript:
                r"\bon\w+=['\"].*?['\"]"  # onclick="..."
            ],
            'path_traversal': [
                r"\.\./",  # ../
                r"%2e%2e%2f",  # ../
                r"\\\.\\.\\"  # \..\
            ],
            'command_injection': [
                r"\b(?:;|\||&)+[\s]*(?:(?:c[md]|power)(?:shell)?|bash|sh|python|perl|ruby)\b",
                r"\b(?:;|\||&)+[\s]*(?:cat|echo|rm|cp|mv|touch|wget|curl)\b"
            ],
            'file_inclusion': [
                r"\binclude\(['\"](?:https?|ftp|php|data|expect):", # include("http:
                r"\brequire\(['\"](?:https?|ftp|php|data|expect):", # require("http:
                r"\binclude_once\(['\"](?:https?|ftp|php|data|expect):", # include_once("http:
                r"\brequire_once\(['\"](?:https?|ftp|php|data|expect):" # require_once("http:
            ]
        }
        
        # Use thread-safe tracking for detected attacks
        with self.http_detect_lock:
            # Initialize attack tracking for this IP if not exists
            if not hasattr(self, 'http_attack_tracking'):
                self.http_attack_tracking = {}
                
            if source_ip not in self.http_attack_tracking:
                self.http_attack_tracking[source_ip] = {
                    'sql_injection': 0,
                    'xss': 0,
                    'path_traversal': 0,
                    'command_injection': 0,
                    'file_inclusion': 0,
                    'total': 0,
                    'first_seen': time.time(),
                    'last_seen': time.time()
                }
                
            # Perform signature matching on payload
            detected = False
            attack_types = []
            
            for attack_type, patterns in attack_signatures.items():
                for pattern in patterns:
                    if re.search(pattern, payload, re.IGNORECASE):
                        self.http_attack_tracking[source_ip][attack_type] += 1
                        self.http_attack_tracking[source_ip]['total'] += 1
                        self.http_attack_tracking[source_ip]['last_seen'] = time.time()
                        attack_types.append(attack_type)
                        detected = True
                        break  # Found one pattern of this type, move to next type
            
            # Handle detected attacks
            if detected:
                # Log the attack with details
                attack_str = ", ".join(attack_types)
                logging.warning(f"Application layer attack ({attack_str}) detected from {source_ip}")
                
                # Calculate severity based on attack frequency and variety
                severity = self.http_attack_tracking[source_ip]['total']
                variety = len([t for t, c in self.http_attack_tracking[source_ip].items() 
                           if t not in ['total', 'first_seen', 'last_seen'] and c > 0])
                
                # More diverse attacks = higher severity
                if variety > 1:
                    severity += 10 * variety
                
                # Auto-block for high severity or repeat offenders
                if severity >= 3 or self.http_attack_tracking[source_ip]['total'] >= 5:
                    logging.critical(f"Blocking {source_ip} - Multiple application layer attacks: {attack_str}")
                    return True
            
            return detected
    
    def check_packet_drops(self, packet=None):
        """Monitor for packet drops in high traffic environments"""
        try:
            with self.stats_lock:
                if hasattr(self, 'last_packet_check') and hasattr(self, 'packet_count'):
                    current_time = time.time()
                    time_diff = current_time - self.last_packet_check
                    
                    if time_diff > 5:  # Check every 5 seconds
                        self.last_packet_check = current_time
                        expected_packets = self.packet_count * 1.1  # Allow 10% variance
                        
                        # Check if received packets match expected count
                        if self.stats['total_packets'] < expected_packets - 1000:  # Significant drop
                            logging.warning(f"Possible packet dropping detected! Expected ~{int(expected_packets)}, got {self.stats['total_packets']}")
                            print(f"{Fore.YELLOW}[!] Possible packet dropping detected! Network may be saturated{Style.RESET_ALL}")
                            
                        self.packet_count = self.stats['total_packets']
                else:
                    self.last_packet_check = time.time()
                    self.packet_count = self.stats['total_packets']
        except Exception as drop_err:
            logging.error(f"Packet drop detection error: {str(drop_err)}")
            
        # Check if packet was provided for standard attack detection
        if packet is not None:
            try:
                ip_src = packet[IP].src if IP in packet else '0.0.0.0'
                if self.detect_attacks(packet):
                    try:
                        self.block_ip(ip_src, reason="Network attack")
                        self.stats['blocked_packets'] += 1
                        self.stats['attacks_detected'] += 1
                        print(f"{Fore.RED}[!] Attack detected and blocked from: {ip_src}{Style.RESET_ALL}")
                        logging.warning(f"Attack detected and blocked from: {ip_src}")
                    except Exception as block_err:
                        logging.error(f"Error blocking attacker {ip_src}: {str(block_err)}")
            except Exception as detect_err:
                logging.error(f"Attack detection error: {str(detect_err)}")
            
            # Update stats
            self.stats['total_packets'] += 1
            
            try:
                # Performance monitoring for high-speed networks
                if 'start_time' in locals():
                    processing_time = time.time() - start_time
                    if processing_time > 0.01:  # Track performance issues
                        if not hasattr(self, 'performance_issues'):
                            self.performance_issues = 0
                        self.performance_issues += 1
                        
                        if self.performance_issues % 100 == 0:
                            logging.warning(f"Performance degradation: {processing_time:.4f}s per packet, may not keep up with gigabit speeds")
                            self.high_load = True
                
                # Periodic reporting
                if self.stats['total_packets'] % 1000 == 0:
                    print(f"{Fore.CYAN}[*] Processed {self.stats['total_packets']} packets, blocked {self.stats['blocked_packets']} packets{Style.RESET_ALL}")
            except Exception as e:
                # Critical error - top level exception handler ensures packet capture thread never dies
                logging.error(f"Critical error in packet handler: {str(e)}")
                print(f"{Fore.RED}[!] Critical error in packet handler: {str(e)}{Style.RESET_ALL}")
                
                # Track errors
                if not hasattr(self, 'error_count'):
                    self.error_count = 0
                self.error_count += 1
                
                # Alert on many errors
                if self.error_count % 50 == 0:
                    print(f"{Fore.RED}[!!!] Multiple errors occurring: {self.error_count}. Check logs.{Style.RESET_ALL}")
                    logging.critical(f"Multiple packet handler errors: {self.error_count}. System may be unstable.")
                
            # Try to continue processing

    def _enforce_memory_limits(self):
        """Enforce memory limits on tracking dictionaries to prevent unbounded growth"""
        try:
            # Memory limits for various trackers
            max_connections = 10000  # Maximum number of tracked connections
            max_packet_rates = 5000  # Maximum number of tracked IPs for packet rates
            max_tcp_flags = 2000     # Maximum number of IPs tracked for TCP flags
            max_history_items = 100  # Maximum history items per tracking entry
            
            # Use locks to prevent race conditions during cleanup
            with self.connection_lock:
                # Limit connection tracker
                if hasattr(self, 'connection_tracker') and len(self.connection_tracker) > max_connections:
                    # Find oldest entries based on last_seen timestamp
                    sorted_keys = sorted(self.connection_tracker.keys(), 
                                        key=lambda k: self.connection_tracker[k].get('last_seen', 0))
                    # Keep only the newest entries
                    for old_key in sorted_keys[:len(sorted_keys) - max_connections]:
                        del self.connection_tracker[old_key]
                    logging.debug(f"Pruned connection tracker to {max_connections} entries")
            
            with self.packet_rates_lock:
                # Limit packet rates tracker
                if hasattr(self, 'packet_rates') and len(self.packet_rates) > max_packet_rates:
                    # Find oldest entries based on timestamp
                    sorted_ips = sorted(self.packet_rates.keys(), 
                                        key=lambda k: self.packet_rates[k].get('timestamp', 0))
                    # Keep only the newest entries
                    for old_ip in sorted_ips[:len(sorted_ips) - max_packet_rates]:
                        del self.packet_rates[old_ip]
                    logging.debug(f"Pruned packet rates tracker to {max_packet_rates} entries")
            
            with self.tcp_flags_lock:
                # Limit TCP flags tracker
                if hasattr(self, 'tcp_flags_tracker') and len(self.tcp_flags_tracker) > max_tcp_flags:
                    # Find oldest entries based on last_seen timestamp
                    sorted_ips = sorted(self.tcp_flags_tracker.keys(), 
                                        key=lambda k: self.tcp_flags_tracker[k].get('last_seen', 0))
                    # Keep only the newest entries
                    for old_ip in sorted_ips[:len(sorted_ips) - max_tcp_flags]:
                        del self.tcp_flags_tracker[old_ip]
                    logging.debug(f"Pruned TCP flags tracker to {max_tcp_flags} entries")
                    
                # Limit history sizes within trackers
                if hasattr(self, 'tcp_flags_tracker'):
                    for ip in self.tcp_flags_tracker:
                        if len(self.tcp_flags_tracker[ip].get('flags_history', [])) > max_history_items:
                            self.tcp_flags_tracker[ip]['flags_history'] = \
                                self.tcp_flags_tracker[ip]['flags_history'][-max_history_items:]
                            
        except Exception as e:
            logging.error(f"Error enforcing memory limits: {str(e)}")
                
    # Basic filtering - skip whitelisted and local IPs
    def filter_ip(self, ip_addr):
        """Filter IP addresses based on security policies"""
        try:
            if not isinstance(ip_addr, str):
                return False
                
            # Check if IP is valid
            try:
                ipaddress.ip_address(ip_addr)
            except ValueError:
                logging.warning(f"Invalid IP address format: {ip_addr}")
                return False
                
            # Apply filtering rules
            if ip_addr in self.blocked_ips:
                return True  # Block this IP
                
            # Check if IP is in whitelist
            if hasattr(self, 'whitelist') and ip_addr in self.whitelist:
                return False  # Don't block whitelisted IPs
                
            return False  # Default: don't block
        except Exception as e:
            logging.error(f"Error in IP filtering: {str(e)}")
            return False
            
    # cleanup_data functionality merged into cleanup_old_data
    
    def check_ip_rep_and_block(self, ip_src):
        """Check IP reputation and block if poor reputation"""
        try:
            reputation_check = self._check_ip_reputation(ip_src)
            if reputation_check and reputation_check.get('score', 100) < 20:
                try:
                    self.block_ip(ip_src, reason="Low reputation score")
                    with self.stats_lock:
                        self.stats['blocked_packets'] += 1
                        self.stats['reputation_blocks'] += 1
                    print(f"{Fore.RED}[!] Blocked low reputation IP: {ip_src} (Score: {reputation_check.get('score', 0)}){Style.RESET_ALL}")
                    logging.warning(f"Blocked low reputation IP: {ip_src} (Score: {reputation_check.get('score', 0)})")
                    return True
                except Exception as block_err:
                    logging.error(f"Error blocking IP {ip_src}: {str(block_err)}")
        except Exception as rep_err:
            logging.error(f"Error checking IP reputation: {str(rep_err)}")
            
        return False
    
    @lru_cache(maxsize=1000)
    def _check_ip_reputation(self, ip):
        """Check IP reputation using local and online databases - now with LRU caching for performance"""
        # Default score and categories
        result = {
            'score': 100,  # Higher is better
            'categories': []
        }
        
        try:
            # Check local reputation database first
            if hasattr(self, 'ip_reputation_db') and ip in self.ip_reputation_db:
                return self.ip_reputation_db[ip]
                
            # Check for known malicious IP patterns
            if self.is_suspicious_ip_pattern(ip):
                result['score'] = 10
                result['categories'].append('suspicious_pattern')
                
            # Check online reputation services if available and not already low score
            if result['score'] > 50 and hasattr(self, 'use_online_reputation') and self.use_online_reputation:
                try:
                    # This would normally call an API but we'll simulate it
                    # to avoid making actual external calls in this example
                    pass
                except Exception:
                    # Fail silently on API errors
                    pass
        except Exception as e:
            logging.error(f"Error in IP reputation check: {str(e)}")
            
        return result
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of a string - measure of randomness"""
        if not data:
            return 0
        
        # Count character frequencies
        char_count = {}
        for char in data:
            if char in char_count:
                char_count[char] += 1
            else:
                char_count[char] = 1
        
        # Calculate entropy
        entropy = 0
        for count in char_count.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
        
        return entropy
        
    def is_suspicious_ip_pattern(self, ip):
        """Check if the IP address matches suspicious patterns"""
        try:
            if not ip or not isinstance(ip, str):
                return False
                
            # Check for private IPv4 ranges (not suspicious)
            if self.is_private_ip(ip):
                return False
            
            # Check for known patterns used in attacks
            suspicious_patterns = [
                r'^192\.168\.',  # Local IPs sometimes used in spoofing
                r'^10\.',        # Local IPs sometimes used in spoofing
                r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',  # Local IPs sometimes used in spoofing
                r'^169\.254\.',  # Link-local IPs sometimes abused
                r'^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.',  # CGNAT space often abused
            ]
            
            for pattern in suspicious_patterns:
                if re.match(pattern, ip):
                    return True
            
            # Pattern 2: Check for sequential IP octets which can indicate automated tools
            octets = ip.split('.')
            if len(octets) == 4:  # IPv4
                if octets[0] == octets[1] == octets[2]:
                    return True
                    
                # Check for binary patterns in the last octet
                # that are often used by scanning tools
                if octets[3] in ['1', '255', '254']:
                    return True
            
            return False
        except Exception as e:
            logging.error(f"Error checking suspicious IP pattern: {str(e)}")
            return False
                
    def track_connections_and_rates(self, ip_src, ip_dst):
        """Update connection tracking and enforce rate limiting"""
        # Update tracking with exception handling
        try:
            self.update_connection_tracker(ip_src, ip_dst)
        except Exception as conn_err:
            logging.error(f"Connection tracking error: {str(conn_err)}")
                    
        try:
            # Rate limiting with built-in packet dropping for DoS protection
            return self.update_packet_rates(ip_src)
        except Exception as rate_err:
            logging.error(f"Packet rate tracking error: {str(rate_err)}")
            return True  # Continue processing if rate tracking fails
                
    def handle_application_layer_attack(self, packet, ip_src):
        """Detect and respond to application layer attacks"""
        try:
            if self.check_application_layer_attacks(packet):
                try:
                    self.block_ip(ip_src, reason="Application layer attack")
                    with self.stats_lock:
                        self.stats['blocked_packets'] += 1
                        self.stats['app_layer_attacks'] = self.stats.get('app_layer_attacks', 0) + 1
                    print(f"{Fore.RED}[!] Application layer attack detected from: {ip_src}{Style.RESET_ALL}")
                    logging.warning(f"Application layer attack detected from: {ip_src}")
                    return True
                except Exception as block_err:
                    logging.error(f"Error blocking application layer attacker {ip_src}: {str(block_err)}")
        except Exception as app_err:
            logging.error(f"Application layer analysis error: {str(app_err)}")
            
        return False
                
    def handle_standard_attacks(self, packet, ip_src):
        """Detect and block standard network attacks"""
        try:
            if self.detect_attacks(packet):
                try:
                    self.block_ip(ip_src, reason="Network attack")
                    with self.stats_lock:
                        self.stats['blocked_packets'] += 1
                        self.stats['attacks_detected'] += 1
                    print(f"{Fore.RED}[!] Attack detected and blocked from: {ip_src}{Style.RESET_ALL}")
                    logging.warning(f"Attack detected and blocked from: {ip_src}")
                    return True
                except Exception as block_err:
                    logging.error(f"Error blocking attacker {ip_src}: {str(block_err)}")
        except Exception as detect_err:
            logging.error(f"Attack detection error for packet from {ip_src}: {str(detect_err)}")
        
        return False
                
    def monitor_performance(self, start_time):
        """Monitor packet processing performance and track issues"""
        try:
            with self.stats_lock:
                self.stats['total_packets'] += 1
                    
            # Performance monitoring for high-speed networks
            processing_time = time.time() - start_time
            if processing_time > 0.01:  # Track performance issues
                with self.stats_lock:
                    if not hasattr(self, 'performance_issues'):
                        self.performance_issues = 0
                    self.performance_issues += 1
                            
                    if self.performance_issues % 100 == 0:
                        logging.warning(f"Performance degradation: {processing_time:.4f}s per packet, may not keep up with gigabit speeds")
                        self.high_load = True
                
                # Periodic reporting
                if self.stats['total_packets'] % 1000 == 0:
                    print(f"{Fore.CYAN}[*] Processed {self.stats['total_packets']} packets, blocked {self.stats['blocked_packets']} packets{Style.RESET_ALL}")
        except Exception as e:
            # Critical error - top level exception handler ensures packet capture thread never dies
            logging.error(f"Critical error in packet handler: {str(e)}")
            print(f"{Fore.RED}[!] Critical error in packet handler: {str(e)}{Style.RESET_ALL}")
            
            # Track errors
            if not hasattr(self, 'error_count'):
                self.error_count = 0
            self.error_count += 1
            
            # Alert on many errors
            if self.error_count % 50 == 0:
                print(f"{Fore.RED}[!!!] Multiple errors occurring: {self.error_count}. Check logs.{Style.RESET_ALL}")
                logging.critical(f"Multiple packet handler errors: {self.error_count}. System may be unstable.")
    
    def _enforce_memory_limits(self):
        """Enforce memory limits on tracking dictionaries to prevent unbounded growth"""
        try:
            # Memory limits for various trackers
            max_connections = 10000  # Maximum number of tracked connections
            max_packet_rates = 5000  # Maximum number of tracked IPs for packet rates
            max_tcp_flags = 2000     # Maximum number of IPs tracked for TCP flags
            max_history_items = 100  # Maximum history items per tracking entry
            
            # Limit connection tracker
            if hasattr(self, 'connection_tracker') and len(self.connection_tracker) > max_connections:
                # Remove oldest entries based on timestamp
                sorted_keys = sorted(self.connection_tracker.keys(), 
                                     key=lambda k: self.connection_tracker[k]['timestamp'])
                # Keep only the newest entries
                for old_key in sorted_keys[:len(sorted_keys) - max_connections]:
                    del self.connection_tracker[old_key]
                logging.debug(f"Pruned connection tracker to {max_connections} entries")
                
            # Limit packet rates tracker
            if hasattr(self, 'packet_rates') and len(self.packet_rates) > max_packet_rates:
                # Remove oldest entries based on timestamp
                sorted_ips = sorted(self.packet_rates.keys(), 
                                     key=lambda k: self.packet_rates[k]['timestamp'])
                # Keep only the newest entries
                for old_ip in sorted_ips[:len(sorted_ips) - max_packet_rates]:
                    del self.packet_rates[old_ip]
                logging.debug(f"Pruned packet rates tracker to {max_packet_rates} entries")
            
            # Limit TCP flags tracker
            if hasattr(self, 'tcp_flags_tracker') and len(self.tcp_flags_tracker) > max_tcp_flags:
                # Remove oldest entries based on last_seen
                sorted_ips = sorted(self.tcp_flags_tracker.keys(), 
                                     key=lambda k: self.tcp_flags_tracker[k]['last_seen'])
                # Keep only the newest entries
                for old_ip in sorted_ips[:len(sorted_ips) - max_tcp_flags]:
                    del self.tcp_flags_tracker[old_ip]
                logging.debug(f"Pruned TCP flags tracker to {max_tcp_flags} entries")
                    
            # Limit history sizes within trackers
            if hasattr(self, 'tcp_flags_tracker'):
                for ip in self.tcp_flags_tracker:
                    if len(self.tcp_flags_tracker[ip]['flags_history']) > max_history_items:
                        self.tcp_flags_tracker[ip]['flags_history'] = \
                            self.tcp_flags_tracker[ip]['flags_history'][-max_history_items:]
                            
        except Exception as e:
            logging.error(f"Error enforcing memory limits: {str(e)}")
            print(f"{Fore.RED}[!] Error enforcing memory limits: {str(e)}{Style.RESET_ALL}")
            # Errors here shouldn't stop the program

    def update_connection_tracker(self, ip_src, ip_dst):
        """Update connection tracking information in a thread-safe manner"""
        current_time = time.time()
            
        # Acquire lock to prevent race conditions during multi-threaded operation
        with self.connection_lock:
            if ip_src not in self.connection_tracker:
                self.connection_tracker[ip_src] = {
                    'connections': {},
                    'first_seen': current_time,
                    'last_seen': current_time
                }
            
            if ip_dst not in self.connection_tracker[ip_src]['connections']:
                self.connection_tracker[ip_src]['connections'][ip_dst] = {
                    'count': 1,
                    'first_seen': current_time,
                    'last_seen': current_time
                }
            else:
                self.connection_tracker[ip_src]['connections'][ip_dst]['count'] += 1
                self.connection_tracker[ip_src]['connections'][ip_dst]['last_seen'] = current_time
                    
            self.connection_tracker[ip_src]['last_seen'] = current_time
                
            # Check if we need to enforce memory limits during high load
            connection_count = sum(len(src_data['connections']) for src_data in self.connection_tracker.values())
            if connection_count > 50000:  # If tracking more than 50k connections
                self.high_load = True

    def update_packet_rates(self, ip):
        """Update packet rate tracking for a specific IP with rate limiting"""
        current_time = time.time()
        if ip not in self.packet_rates:
            self.packet_rates[ip] = {
                'count': 1,
                'timestamp': current_time,
                'dropped': 0  # Track dropped packets for high traffic monitoring
            }
        else:
            if current_time - self.packet_rates[ip]['timestamp'] > 1:
                # Reset counters for new second but keep track of history
                dropped = self.packet_rates[ip].get('dropped', 0)
                self.packet_rates[ip] = {
                    'count': 1,
                    'timestamp': current_time,
                    'dropped': dropped
                }
            else:
                # Count for rate limiting
                self.packet_rates[ip]['count'] += 1
                
                # Check for excessively high packet rates (potential DoS)
                if self.packet_rates[ip]['count'] > 1000:  # Configurable threshold
                    # Record dropped packet for statistics
                    self.packet_rates[ip]['dropped'] = self.packet_rates[ip].get('dropped', 0) + 1
                    
                    # Log every 100 dropped packets to avoid log flooding
                    if self.packet_rates[ip]['dropped'] % 100 == 0:
                        logging.warning(f"High traffic rate from {ip}: {self.packet_rates[ip]['count']} packets/sec, "
                                      f"dropped {self.packet_rates[ip]['dropped']} packets")
                    
                    # Record in stats if not exists
                    if not hasattr(self.stats, 'dropped_packets'):
                        self.stats['dropped_packets'] = 0
                    
                    self.stats['dropped_packets'] = self.stats.get('dropped_packets', 0) + 1
                    
                    # Return False to indicate packet should be dropped
                    return False
            
        # Return True to indicate packet processing should continue
        return True

    def detect_attacks(self, packet):
        """Comprehensive attack detection - Integrated with Linux security features"""
        if not IP in packet:
            return False
            
        ip_src = packet[IP].src
        
        # Skip local network traffic completely
        if self.is_local_network(ip_src) or ip_src in self.local_ips:
            return False
        
        # Skip whitelisted IPs
        if self.is_ip_in_whitelist(ip_src):
            return False
        
        # Skip router and gateway IPs (unless configured otherwise)
        if not hasattr(self, 'monitor_routers') or not self.monitor_routers:
            if ip_src.endswith('.1') or ip_src.endswith('.254'):
                return False
                
        # Initialize trackers if needed
        current_time = time.time()
        if not hasattr(self, 'last_defense_status_report'):
            self.last_defense_status_report = current_time
            self.defense_status = {'syn': False, 'udp': False, 'icmp': False, 'fragment': False}
            self.defense_ip_block_list = set()
        
        # Track IP reputation and block if needed
        try:
            reputation_check = self.check_ip_reputation(ip_src)
            if reputation_check and reputation_check.get('score', 100) < 20:  # Very low reputation
                if ip_src not in self.defense_ip_block_list:
                    logging.warning(f"Blocking malicious IP {ip_src}: reputation score {reputation_check.get('score', 0)}/100")
                    # Block IP using iptables if Linux
                    if not hasattr(self, 'security_level') or self.security_level >= 2:
                        try:
                            subprocess.run(
                                f"iptables -A INPUT -s {ip_src} -j DROP", 
                                shell=True, check=True
                            )
                            self.defense_ip_block_list.add(ip_src)
                            logging.info(f"Successfully blocked IP {ip_src} at firewall level")
                            print(f"{Fore.YELLOW}[+] IP {ip_src} blocked at firewall level{Style.RESET_ALL}")
                        except Exception as e:
                            logging.error(f"Failed to block IP {ip_src}: {str(e)}")
                return True
        except Exception as e:
            logging.debug(f"Error checking IP reputation: {str(e)}")
        
        # Check for spoofing attacks first
        if self.check_ip_spoofing(packet):
            self.stats['spoofing_attempts'] += 1
            logging.warning(f"IP spoofing detected from {ip_src}")
            print(f"{Fore.RED}[!] IP Spoofing detected from: {ip_src}{Style.RESET_ALL}")
            
            # Apply Linux-specific defenses
            if not hasattr(self, 'linux_antispoofing_applied') or not self.linux_antispoofing_applied:
                try:
                    # rp_filter = Reverse Path Filtering
                    subprocess.run(
                        "sysctl -w net.ipv4.conf.all.rp_filter=1", 
                        shell=True, check=True
                    )
                    subprocess.run(
                        "sysctl -w net.ipv4.conf.default.rp_filter=1", 
                        shell=True, check=True
                    )
                    logging.info("Successfully enabled Linux kernel reverse path filtering")
                    self.linux_antispoofing_applied = True
                except Exception as e:
                    logging.error(f"Failed to enable Linux anti-spoofing: {str(e)}")
                    
            return True
                
        # Check for fragment attacks
        if self.check_fragment_attack(packet):
            self.stats['fragment_attacks'] += 1
            logging.warning(f"Fragment attack detected from {ip_src}")
            print(f"{Fore.RED}[!] Fragment attack detected from: {ip_src}{Style.RESET_ALL}")
            return True
        
        # Check for flood attacks using enhanced methods
        attack_detected = False
        attack_type = ""
        
        # Check for SYN flood
        if TCP in packet and self.check_syn_flood(packet):
            self.stats['syn_floods'] += 1
            attack_detected = True
            attack_type = "SYN Flood"
            self.defense_status['syn'] = True
                
        # Check for UDP flood
        elif UDP in packet and self.check_udp_flood(packet):
            self.stats['udp_floods'] += 1
            attack_detected = True
            attack_type = "UDP Flood"
            self.defense_status['udp'] = True
                
        # Check for ICMP flood
        elif ICMP in packet and self.check_icmp_flood(packet):
            self.stats['icmp_floods'] += 1
            attack_detected = True
            attack_type = "ICMP Flood"
            self.defense_status['icmp'] = True
        
        # If any attack detected, add to tracking and log    
        if attack_detected:
            # Track attack source
            if not hasattr(self, 'attack_sources'):
                self.attack_sources = {}
                
            if ip_src not in self.attack_sources:
                self.attack_sources[ip_src] = {
                    'first_attack': current_time,
                    'last_attack': current_time,
                    'types': {attack_type: 1},
                    'blocked': False
                }
            else:
                self.attack_sources[ip_src]['last_attack'] = current_time
                if attack_type in self.attack_sources[ip_src]['types']:
                    self.attack_sources[ip_src]['types'][attack_type] += 1
                else:
                    self.attack_sources[ip_src]['types'][attack_type] = 1
                    
            # Log the detected attack
            logging.warning(f"{attack_type} detected from {ip_src}")
            print(f"{Fore.RED}[!] {attack_type} detected from: {ip_src}{Style.RESET_ALL}")
            
            # For persistent offenders, block at Linux firewall level
            if hasattr(self, 'security_level') and self.security_level >= 3:
                source_data = self.attack_sources[ip_src]
                attack_types = len(source_data['types'])
                total_attacks = sum(source_data['types'].values())
                
                if attack_types > 2 or total_attacks > 5:
                    if not source_data['blocked'] and ip_src not in self.defense_ip_block_list:
                        try:
                            try:
                                ipaddress.ip_address(ip_src)
                                subprocess.run(
                                    ['iptables', '-A', 'INPUT', '-s', ip_src, '-j', 'DROP'],
                                    shell=False, check=True
                                )
                                source_data['blocked'] = True
                                self.defense_ip_block_list.add(ip_src)
                            except ValueError:
                                logging.error(f"Invalid IP address attempted to be blocked: {ip_src}")
                                print(f"{Fore.RED}[!] Invalid IP address detected: {ip_src}{Style.RESET_ALL}")
                                return True
                            logging.info(f"Persistent attacker {ip_src} blocked at firewall level")
                            print(f"{Fore.YELLOW}[+] Persistent attacker {ip_src} blocked at firewall level{Style.RESET_ALL}")
                        except Exception as e:
                            logging.error(f"Failed to block persistent attacker {ip_src}: {str(e)}")
            
            return True
            
        # Check for unusual TCP flags combinations (advanced scan techniques)
        if TCP in packet and self.check_unusual_tcp_flags(packet):
            if not 'unusual_flags' in self.stats:
                self.stats['unusual_flags'] = 0
            self.stats['unusual_flags'] += 1
            logging.warning(f"Unusual TCP flags pattern detected from {ip_src}")
            print(f"{Fore.RED}[!] Advanced scan technique detected from: {ip_src}{Style.RESET_ALL}")
            
            # Add to defense block list for persistent offenders
            if ip_src not in self.defense_ip_block_list:
                self.defense_ip_block_list.add(ip_src)
                
            return True
            
        # Periodically check port scans (separate from flood attacks)
        if hasattr(self, 'last_portscan_check'):
            if current_time - self.last_portscan_check > 10:  # Every 10 seconds
                self.last_portscan_check = current_time
                if self.check_port_scan(ip_src):
                    self.stats['port_scans'] += 1
                    logging.warning(f"Port scan detected from {ip_src}")
                    print(f"{Fore.RED}[!] Port scan detected from: {ip_src}{Style.RESET_ALL}")
                    return True
        else:
            self.last_portscan_check = current_time
            
        # Status reporting for defense mechanisms
        if current_time - self.last_defense_status_report > 300:  # Every 5 minutes
            self.last_defense_status_report = current_time
            active_defenses = []
            
            # Thread-safe access to defense_status dictionary
            with self.defense_lock:  # Using existing defense_lock or need to add it if not exists
                if self.defense_status.get('syn', False):  
                    active_defenses.append("SYN flood protection")
                if self.defense_status.get('udp', False):
                    active_defenses.append("UDP flood protection")
                if self.defense_status.get('icmp', False):
                    active_defenses.append("ICMP flood protection")
                if self.defense_status.get('fragment', False):
                    active_defenses.append("Fragment attack protection")
            
            # Actually use the active_defenses information
            if active_defenses:
                defense_msg = f"Active defenses: {', '.join(active_defenses)}"
                logging.info(defense_msg)
                if self.verbose:
                    print(f"{Fore.CYAN}[INFO] {defense_msg}{Style.RESET_ALL}")
                
        # No attack detected
        return False
        
    def check_syn_flood(self, packet):
        """Enhanced SYN flood detection with Linux-specific defenses"""
        # Ensure it's a TCP packet
        if not TCP in packet:
            return False
            
        # Check for SYN flag
        if not packet[TCP].flags & 0x02:
            return False
            
        ip_src = packet[IP].src
        tcp_dport = packet[TCP].dport
        current_time = time.time()
        
        # Using lock to prevent race conditions
        with self.tcp_flags_lock:
            # Initialize SYN flood trackers if not exists
            if not hasattr(self, 'syn_tracker'):
                self.syn_tracker = {}
                self.linux_sysctl_applied = False
            
            # Initialize or update SYN count for this source IP
            if ip_src not in self.syn_tracker:
                self.syn_tracker[ip_src] = {
                    'count': 1, 
                    'first_syn': current_time,
                    'last_syn': current_time,
                    'ports': {tcp_dport: 1},
                    'completed': 0
                }
            else:
                # Update existing tracker
                tracker = self.syn_tracker[ip_src]
                tracker['count'] += 1
                tracker['last_syn'] = current_time
                
                # Track targeted ports
                if tcp_dport in tracker['ports']:
                    tracker['ports'][tcp_dport] += 1
                else:
                    tracker['ports'][tcp_dport] = 1
            
            # Calculate metrics for detection
            tracker = self.syn_tracker[ip_src]
            syn_count = tracker['count']
            time_window = current_time - tracker['first_syn']
            ports_targeted = len(tracker['ports'])
            syn_rate = syn_count / max(time_window, 0.1)  # Avoid division by zero
            
            # Attack Pattern 1: High rate of SYN packets - with improved thresholds to reduce false positives
            if time_window > 2 and syn_rate > 150 and syn_count > 300:  # More strict conditions
                # Additional check for legitimate connections
                if ip_src in self.whitelist or self._check_legitimate_connection(ip_src):
                    logging.debug(f"Ignored potential false positive SYN detection from whitelisted/legitimate IP {ip_src}")
                    return False
                    
                self._activate_linux_defenses()
                logging.warning(f"SYN flood detected from {ip_src}: {syn_count} SYNs in {time_window:.2f}s, rate: {syn_rate:.2f}/s")
                return True
            
            # Attack Pattern 2: Multiple ports targeted quickly - with context awareness
            if ports_targeted > 30 and time_window < 5 and syn_count > 100:  # More restrictive
                # Check if this might be legitimate service discovery or application behavior
                if self._is_common_port_pattern(tracker['ports']):
                    logging.debug(f"Ignored potential false positive port scan from {ip_src} - matches common pattern")
                    return False
                    
                self._activate_linux_defenses()
                logging.warning(f"Fast port scan or distributed SYN flood from {ip_src}: targeting {ports_targeted} ports in {time_window:.2f}s")
                return True
                
            # Reset tracker if window is too large to avoid stale data
            if time_window > 60:  # 1 minute window
                self.syn_tracker[ip_src] = {
                    'count': 1, 
                    'first_syn': current_time,
                    'last_syn': current_time,
                    'ports': {tcp_dport: 1},
                    'completed': 0
                }
                
            # Clean up trackers periodically
                if hasattr(self, 'last_syn_cleanup') and current_time - getattr(self, 'last_syn_cleanup', 0) > 60:
                    self.last_syn_cleanup = current_time
                    stale_ips = []
                    for ip, data in self.syn_tracker.items():
                        if current_time - data.get('last_syn', 0) > 300:  # 5 minutes
                            stale_ips.append(ip)
                    
                    for ip in stale_ips:
                        del self.syn_tracker[ip]
                        
                    if stale_ips:
                        logging.debug(f"Cleaned up {len(stale_ips)} stale SYN trackers")
            
        return False
    
    def _check_legitimate_connection(self, ip_src):
        """Determine if an IP is likely a legitimate connection even with high traffic
        
        This reduces false positives by checking if the IP has shown normal connection patterns before,
        is a known service, or is communicating with established sessions
        """
        try:
            # Check if we have connection history for this IP
            if hasattr(self, 'connection_tracker') and ip_src in self.connection_tracker:
                conn_data = self.connection_tracker[ip_src]
                
                # If we've seen completed handshakes from this IP, it's likely legitimate
                if conn_data.get('completed_handshakes', 0) > 5:
                    return True
                    
                # If we've seen successful data transfer, it's likely legitimate
                if conn_data.get('data_packets', 0) > 10:
                    return True
            
            # Check if it's a common service port that might have burst traffic
            if hasattr(self, 'tcp_flags_tracker') and ip_src in self.tcp_flags_tracker:
                ports = self.tcp_flags_tracker[ip_src].get('ports_targeted', {})
                service_ports = {80, 443, 8080, 8443, 22, 25, 53, 110, 143, 993, 995}
                
                # If communication is primarily with standard service ports
                if ports and all(port in service_ports for port in ports):
                    return True
            
            return False
            
        except Exception as e:
            logging.error(f"Error in legitimate connection check for {ip_src}: {str(e)}")
            return False
            
    def _is_common_port_pattern(self, ports):
        """Check if the port access pattern matches known legitimate service discovery
        
        This reduces false positives for services like web browsers that may access multiple
        ports in quick succession for legitimate reasons
        """
        try:
            # No ports to check
            if not ports:
                return False
                
            # Common patterns we want to whitelist
            common_patterns = [
                # Web browsing pattern (HTTP, HTTPS, alt HTTP ports)
                {80, 443, 8080, 8443},
                # Email pattern (SMTP, IMAP, POP3, secure variants)
                {25, 143, 110, 993, 995},
                # DNS and web combined
                {53, 80, 443}
            ]
            
            # Get the set of ports being accessed
            port_set = set(ports.keys())
            
            # Check if this matches any of our common patterns
            for pattern in common_patterns:
                # If the intersection covers most of the accessed ports, likely legitimate
                intersection = pattern & port_set
                if len(intersection) >= min(3, len(port_set)):
                    return True
                    
            # Check if ports are in a narrow range (possible service discovery)
            if port_set and max(port_set) - min(port_set) < 20 and len(port_set) < 15:
                return True
                
            return False
            
        except Exception as e:
            logging.error(f"Error in common port pattern check: {str(e)}")
            return False
    
    def _activate_linux_defenses(self):
        """Activate Linux kernel defenses against SYN flood attacks"""
        if not hasattr(self, 'linux_sysctl_applied') or not self.linux_sysctl_applied:
            try:
                # TCP SYN cookie protection
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_syncookies=1'], check=True)
                # Reduce SYN-ACK retries
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_synack_retries=2'], check=True)
                # Increase backlog queue
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_max_syn_backlog=2048'], check=True)
                # Enable protection against time-wait assassination
                subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_rfc1337=1'], check=True)
                # Drop ICMP redirects
                subprocess.run(['sysctl', '-w', 'net.ipv4.conf.all.accept_redirects=0'], check=True)
                # Log martian packets
                subprocess.run(['sysctl', '-w', 'net.ipv4.conf.all.log_martians=1'], check=True)
                
                self.linux_sysctl_applied = True
                logging.info("Linux kernel defenses activated against SYN flood attacks")
            except Exception as e:
                logging.error(f"Failed to activate Linux kernel defenses: {str(e)}")
    

    def check_udp_flood(self, packet):
        """Advanced UDP flood attack detection and Linux defense"""
        if not (IP in packet and UDP in packet):
            return False
            
        ip_src = packet[IP].src
        udp_dport = packet[UDP].dport
        pkt_len = len(packet)
        current_time = time.time()
        
        # Initialize UDP flood trackers if not exists
        if not hasattr(self, 'udp_tracker'):
            self.udp_tracker = {}
            self.udp_ports_tracker = {}
            self.common_udp_ports = [53, 123, 161, 1900, 5353]  # Common UDP service ports
            self.linux_udp_defense_applied = False
        
        # Initialize or update UDP count for this source IP
        if ip_src not in self.udp_tracker:
            self.udp_tracker[ip_src] = {
                'count': 1, 
                'first_packet': current_time,
                'last_packet': current_time,
                'ports': {udp_dport: 1},
                'bytes': pkt_len,
                'amplification_candidate': False
            }
        else:
            # Update existing tracker
            tracker = self.udp_tracker[ip_src]
            tracker['count'] += 1
            tracker['last_packet'] = current_time
            tracker['bytes'] += pkt_len
            
            # Track targeted ports
            if udp_dport in tracker['ports']:
                tracker['ports'][udp_dport] += 1
            else:
                tracker['ports'][udp_dport] = 1
                
        # Track UDP ports (for service port floods)
        if udp_dport not in self.udp_ports_tracker:
            self.udp_ports_tracker[udp_dport] = {
                'count': 1,
                'sources': {ip_src: 1},
                'first_packet': current_time,
                'is_service': udp_dport in self.common_udp_ports
            }
        else:
            port_tracker = self.udp_ports_tracker[udp_dport]
            port_tracker['count'] += 1
            if ip_src in port_tracker['sources']:
                port_tracker['sources'][ip_src] += 1
            else:
                port_tracker['sources'][ip_src] = 1
        
        # Calculate metrics for detection
        tracker = self.udp_tracker[ip_src]
        udp_count = tracker['count']
        time_window = current_time - tracker['first_packet']
        ports_targeted = len(tracker['ports'])
        bytes_per_second = tracker['bytes'] / max(time_window, 0.1)  # Avoid division by zero
        packets_per_second = udp_count / max(time_window, 0.1)
        
        # Look for UDP amplification pattern:
        # Common pattern: small packets to port 53 (DNS), 123 (NTP), 161 (SNMP), etc.
        if udp_dport in self.common_udp_ports and pkt_len < 100:
            tracker['amplification_candidate'] = True
        
        # Attack Pattern 1: High packet rate to single source
        if time_window > 1 and packets_per_second > 500:  # More than 500 UDP packets per second
            self._activate_linux_udp_defenses()
            logging.warning(f"UDP flood detected from {ip_src}: {udp_count} packets in {time_window:.2f}s, rate: {packets_per_second:.2f}/s")
            return True
        
        # Attack Pattern 2: High bandwidth usage
        if bytes_per_second > 1000000:  # More than 1 MB/s
            self._activate_linux_udp_defenses()
            logging.warning(f"UDP bandwidth flood from {ip_src}: {bytes_per_second/1024/1024:.2f} MB/s")
            return True
            
        # Attack Pattern 3: Multiple ports targeted quickly (UDP port scan)
        if ports_targeted > 30 and time_window < 10:
            logging.warning(f"UDP port scan from {ip_src}: targeting {ports_targeted} ports in {time_window:.2f}s")
            return True
            
        # Attack Pattern 4: Service-specific UDP flood (targeting specific services)
        for port, port_data in self.udp_ports_tracker.items():
            if port_data['is_service'] and current_time - port_data['first_packet'] < 5:
                # If many sources target the same service port in short time
                if len(port_data['sources']) > 20:
                    self._activate_linux_udp_defenses()
                    logging.warning(f"Distributed UDP flood detected on service port {port}: {len(port_data['sources'])} sources")
                    return True
                # If one source sends many packets to a service port
                elif port_data['count'] > 300 and len(port_data['sources']) < 5:
                    self._activate_linux_udp_defenses()
                    logging.warning(f"UDP service flood detected on port {port}: {port_data['count']} packets")
                    return True
            
        # Reset tracker if window is too large to avoid stale data
        if time_window > 60:  # 1 minute window
            self.udp_tracker[ip_src] = {
                'count': 1, 
                'first_packet': current_time,
                'last_packet': current_time,
                'ports': {udp_dport: 1},
                'bytes': pkt_len,
                'amplification_candidate': tracker.get('amplification_candidate', False)
            }
            
        # Clean up trackers periodically
        if hasattr(self, 'last_udp_cleanup') and current_time - getattr(self, 'last_udp_cleanup', 0) > 60:
            self.last_udp_cleanup = current_time
            
            # Clean IP trackers
            stale_ips = []
            for ip, data in self.udp_tracker.items():
                if current_time - data.get('last_packet', 0) > 300:  # 5 minutes
                    stale_ips.append(ip)
            
            for ip in stale_ips:
                del self.udp_tracker[ip]
                
            # Clean port trackers
            stale_ports = []
            for port, data in self.udp_ports_tracker.items():
                if current_time - data.get('first_packet', 0) > 300:  # 5 minutes
                    stale_ports.append(port)
            
            for port in stale_ports:
                del self.udp_ports_tracker[port]
                
            if stale_ips or stale_ports:
                logging.debug(f"Cleaned up {len(stale_ips)} stale UDP IP trackers and {len(stale_ports)} port trackers")
                
        return False
        
    def _activate_linux_udp_defenses(self):
        """Activate Linux kernel defenses against UDP flood attacks"""
        if hasattr(self, 'linux_udp_defense_applied') and self.linux_udp_defense_applied:
            return  # Already applied
            
        try:
            # Common Linux sysctl settings to mitigate UDP floods
            sysctl_commands = [
                # Increase UDP buffer sizes
                'sysctl -w net.core.rmem_max=16777216',  # 16MB max receive buffer
                'sysctl -w net.core.wmem_max=16777216',  # 16MB max send buffer
                # Set UDP memory pressure thresholds
                'sysctl -w net.ipv4.udp_mem="262144 327680 393216"',
                # Connectivity tracking hardening
                'sysctl -w net.netfilter.nf_conntrack_udp_timeout=10',        # Seconds
                'sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=30', # Seconds
                # Rate limit ICMP so attackers can't simply block your ICMP messages
                'sysctl -w net.ipv4.icmp_ratelimit=1000',
                # If DNS server present, limit responses to help prevent amplification
                'if command -v named &> /dev/null; then rndc recursing; fi'
            ]
            
            for cmd in sysctl_commands:
                try:
                    subprocess.run(cmd, shell=True, check=True)
                except Exception as e:
                    logging.error(f"Failed to run UDP defense command '{cmd}': {str(e)}")
                
            logging.info("Successfully activated Linux kernel UDP flood defenses")
            self.linux_udp_defense_applied = True
        except Exception as e:
            logging.error(f"Failed to activate Linux UDP defenses: {str(e)}")
            self.linux_udp_defense_applied = False
        return False

    def check_icmp_flood(self, packet):
        """Advanced ICMP flood attack detection and Linux defense"""
        if not (IP in packet and ICMP in packet):
            return False
            
        ip_src = packet[IP].src
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        pkt_len = len(packet)
        current_time = time.time()
        
        # Initialize ICMP flood trackers if not exists
        if not hasattr(self, 'icmp_tracker'):
            self.icmp_tracker = {}
            # Common ICMP types we want to track specifically
            self.icmp_types = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                8: "Echo Request", 
                11: "Time Exceeded",
                13: "Timestamp",
                15: "Information Request",
                17: "Address Mask Request"
            }
            # Initialize Linux defense flag
            self.linux_icmp_defense_applied = False
            
        # Create type-code key for detailed tracking
        type_code = f"{icmp_type}-{icmp_code}"
        
        # Initialize or update ICMP count for this source IP
        if ip_src not in self.icmp_tracker:
            self.icmp_tracker[ip_src] = {
                'count': 1, 
                'first_packet': current_time,
                'last_packet': current_time,
                'bytes': pkt_len,
                'types': {type_code: 1}
            }
        else:
            # Update existing tracker
            tracker = self.icmp_tracker[ip_src]
            tracker['count'] += 1
            tracker['last_packet'] = current_time
            tracker['bytes'] += pkt_len
            
            # Track ICMP types/codes
            if type_code in tracker['types']:
                tracker['types'][type_code] += 1
            else:
                tracker['types'][type_code] = 1
        
        # Calculate metrics for detection
        tracker = self.icmp_tracker[ip_src]
        icmp_count = tracker['count']
        time_window = current_time - tracker['first_packet']
        bytes_per_second = tracker['bytes'] / max(time_window, 0.1)  # Avoid division by zero
        packets_per_second = icmp_count / max(time_window, 0.1)
        distinct_types = len(tracker['types'])
        
        # Attack Pattern 1: High rate of ICMP packets
        # This is the classic ICMP flood pattern
        if time_window > 1 and packets_per_second > 100:  # More than 100 ICMP packets per second
            self._activate_linux_icmp_defenses()
            logging.warning(f"ICMP flood detected from {ip_src}: {icmp_count} packets in {time_window:.2f}s, rate: {packets_per_second:.2f}/s")
            return True
            
        # Attack Pattern 2: High bandwidth usage (ICMP bandwidth flood)
        if bytes_per_second > 500000:  # More than 500 KB/s of ICMP traffic
            self._activate_linux_icmp_defenses()
            logging.warning(f"ICMP bandwidth flood from {ip_src}: {bytes_per_second/1024:.2f} KB/s")
            return True
            
        # Attack Pattern 3: Echo request flood (ping flood)
        if icmp_type == 8 and time_window > 2:  # Echo request
            echo_count = tracker['types'].get(f"8-0", 0)
            echo_rate = echo_count / time_window
            if echo_rate > 50:  # More than 50 echo requests per second
                self._activate_linux_icmp_defenses()
                logging.warning(f"ICMP ping flood from {ip_src}: {echo_count} echo requests in {time_window:.2f}s")
                return True
                
        # Attack Pattern 4: ICMP type scan or unusual ICMP types
        if distinct_types > 5 and time_window < 60:  # Many different ICMP types in short period
            logging.warning(f"ICMP type scan from {ip_src}: {distinct_types} different ICMP types")
            return True
            
        # Attack Pattern 5: Amplification or DoS via broadcast ping
        if icmp_type == 8 and pkt_len > 1000:  # Large ICMP echo request
            self._activate_linux_icmp_defenses()
            logging.warning(f"Large ICMP packet from {ip_src}: {pkt_len} bytes, possible amplification attack")
            return True
            
        # Reset tracker if window is too large to avoid stale data
        if time_window > 120:  # 2 minute window
            self.icmp_tracker[ip_src] = {
                'count': 1, 
                'first_packet': current_time,
                'last_packet': current_time,
                'bytes': pkt_len,
                'types': {type_code: 1}
            }
            
        # Clean up trackers periodically
        if hasattr(self, 'last_icmp_cleanup') and current_time - getattr(self, 'last_icmp_cleanup', 0) > 120:
            self.last_icmp_cleanup = current_time
            
            # Clean IP trackers
            stale_ips = []
            for ip, data in self.icmp_tracker.items():
                if current_time - data.get('last_packet', 0) > 300:  # 5 minutes
                    stale_ips.append(ip)
            
            for ip in stale_ips:
                del self.icmp_tracker[ip]
                
            if stale_ips:
                logging.debug(f"Cleaned up {len(stale_ips)} stale ICMP trackers")
                
        return False
        
    def _activate_linux_icmp_defenses(self):
        """Activate Linux kernel defenses against ICMP flood attacks"""
        if hasattr(self, 'linux_icmp_defense_applied') and self.linux_icmp_defense_applied:
            return  # Already applied
            
        try:
            # Common Linux sysctl settings to mitigate ICMP floods
            sysctl_commands = [
                # Ignore broadcasts to prevent smurf attacks
                'sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1',
                # Set rate limit for ICMP errors
                'sysctl -w net.ipv4.icmp_ratelimit=100',
                # Ignore bogus ICMP errors
                'sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1',
                # Rate limit logging of invalid addresses
                'sysctl -w net.ipv4.conf.all.log_martians=0',
                # For advanced protection, we can completely ignore ping requests
                # This is done only if the attack persists
                # 'sysctl -w net.ipv4.icmp_echo_ignore_all=1',
            ]
            
            for cmd in sysctl_commands:
                try:
                    subprocess.run(cmd, shell=True, check=True)
                except Exception as e:
                    logging.error(f"Failed to run ICMP defense command '{cmd}': {str(e)}")
            
            # Also apply iptables rules for ICMP rate limiting
            icmp_iptables_cmds = [
                # Rate limit ICMP to 5/second with burst of 10
                'iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/second --limit-burst 10 -j ACCEPT',
                'iptables -A INPUT -p icmp --icmp-type echo-request -j DROP'
            ]
            
            for cmd in icmp_iptables_cmds:
                try:
                    subprocess.run(cmd, shell=True, check=True)
                except Exception as e:
                    logging.error(f"Failed to run ICMP iptables command '{cmd}': {str(e)}")
                
            logging.info("Successfully activated Linux kernel ICMP flood defenses")
            self.linux_icmp_defense_applied = True
        except Exception as e:
            logging.error(f"Failed to activate Linux ICMP defenses: {str(e)}")
            self.linux_icmp_defense_applied = False
        return False

    def check_port_scan(self, ip, threshold_multiplier=1.0):
        """Advanced port scan detection"""
        if not hasattr(self, 'port_scan_tracker'):
            self.port_scan_tracker = {}
            
        current_time = time.time()
        scan_window = 60  # 60-second window
        short_window = 5   # 5-second window for fast scans
        unique_ports = set()
        recent_ports = set()  # For very recent connections (fast scan)
        tcp_syn_ports = set()  # For SYN scans
        tcp_fin_ports = set()  # For FIN scans
        tcp_null_ports = set() # For NULL scans
        tcp_xmas_ports = set() # For XMAS scans
        udp_ports = set()      # For UDP scans
        
        # Get all recent connection attempts from this IP
        for conn in self.connection_tracker:
            if ip in conn:
                conn_time = self.connection_tracker[conn]['timestamp']
                if current_time - conn_time < scan_window:
                    parts = conn.split('-')
                    if len(parts) >= 2:
                        try:
                            port_info = parts[1].split(':')
                            if len(port_info) >= 2:
                                port = port_info[-1]
                                unique_ports.add(port)
                                
                                # Check for very recent connections (possible fast scan)
                                if current_time - conn_time < short_window:
                                    recent_ports.add(port)
                                    
                                # Track connection type if available
                                if len(parts) >= 3 and 'type' in parts[2]:
                                    conn_type = parts[2]['type']
                                    if conn_type == 'tcp_syn':
                                        tcp_syn_ports.add(port)
                                    elif conn_type == 'tcp_fin':
                                        tcp_fin_ports.add(port)
                                    elif conn_type == 'tcp_null':
                                        tcp_null_ports.add(port)
                                    elif conn_type == 'tcp_xmas':
                                        tcp_xmas_ports.add(port)
                                    elif conn_type == 'udp':
                                        udp_ports.add(port)
                        except Exception:
                            pass  # Malformed connection key
        
        # Initialize or update port scan tracker
        if ip not in self.port_scan_tracker:
            self.port_scan_tracker[ip] = {
                'first_seen': current_time,
                'last_seen': current_time,
                'port_count': len(unique_ports),
                'port_history': list(unique_ports),
                'scan_detection_count': 0
            }
        else:
            # Update the tracker
            tracker = self.port_scan_tracker[ip]
            tracker['last_seen'] = current_time
            tracker['port_count'] = max(tracker['port_count'], len(unique_ports))
            
            # Update port history (keep only most recent 100 ports)
            new_ports = [p for p in unique_ports if p not in tracker['port_history']]
            tracker['port_history'].extend(new_ports)
            if len(tracker['port_history']) > 100:
                tracker['port_history'] = tracker['port_history'][-100:]
        
        # Different detection methods
        scan_detected = False
        
        # Method 1: Basic threshold detection (improved)
        base_threshold = 40  # Lower but more accurate threshold with other detection methods
        if len(unique_ports) > (base_threshold * threshold_multiplier):
            scan_detected = True
            logging.warning(f"Port scan detected from {ip} - {len(unique_ports)} ports in {scan_window}s")
        
        # Method 2: Fast scan detection
        fast_scan_threshold = 15
        if len(recent_ports) > fast_scan_threshold:
            scan_detected = True
            logging.warning(f"Fast port scan detected from {ip} - {len(recent_ports)} ports in {short_window}s")
            
        # Method 3: Sequential port scanning
        if len(unique_ports) >= 5:
            port_list = sorted([int(p) for p in unique_ports if p.isdigit()])
            if len(port_list) >= 5:
                # Check for sequential port access
                sequence_count = 0
                for i in range(1, len(port_list)):
                    if port_list[i] == port_list[i-1] + 1:
                        sequence_count += 1
                        if sequence_count >= 4:  # 5 sequential ports
                            scan_detected = True
                            logging.warning(f"Sequential port scan detected from {ip}")
                            break
                    else:
                        sequence_count = 0
        
        # Method 4: Specific scan type detection
        if len(tcp_syn_ports) >= 10:
            scan_detected = True
            logging.warning(f"SYN scan detected from {ip} - {len(tcp_syn_ports)} SYN packets")
        if len(tcp_fin_ports) >= 8:
            scan_detected = True
            logging.warning(f"FIN scan detected from {ip} - {len(tcp_fin_ports)} FIN packets")
        if len(tcp_null_ports) >= 8:
            scan_detected = True
            logging.warning(f"NULL scan detected from {ip} - {len(tcp_null_ports)} NULL packets")
        if len(tcp_xmas_ports) >= 8:
            scan_detected = True
            logging.warning(f"XMAS scan detected from {ip} - {len(tcp_xmas_ports)} XMAS packets")
        
        # Update detection count if scan is detected
        if scan_detected and ip in self.port_scan_tracker:
            self.port_scan_tracker[ip]['scan_detection_count'] += 1
            
        return scan_detected

    def check_dns_amplification(self, packet):
        """Advanced DNS amplification attack detection"""
        # Check for DNS response (UDP port 53)
        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            packet_len = len(packet)
            
            # Initialize DNS amplification tracker if not exists
            if not hasattr(self, 'dns_tracker'):
                self.dns_tracker = {}
            
            # Track source IP
            ip_src = packet[IP].src
            current_time = time.time()
            
            # Case 1: Check for large DNS responses (more severe)
            if src_port == 53:  # DNS server response
                # Store large DNS responses from this source
                if packet_len > 512:  # DNS responses over 512 bytes are suspicious
                    if ip_src not in self.dns_tracker:
                        self.dns_tracker[ip_src] = {
                            'large_responses': 1,
                            'last_update': current_time,
                            'max_size': packet_len,
                            'avg_size': packet_len,
                            'response_count': 1
                        }
                    else:
                        # Update tracker with new information
                        self.dns_tracker[ip_src]['large_responses'] += 1
                        self.dns_tracker[ip_src]['last_update'] = current_time
                        self.dns_tracker[ip_src]['response_count'] += 1
                        
                        # Update max size
                        if packet_len > self.dns_tracker[ip_src]['max_size']:
                            self.dns_tracker[ip_src]['max_size'] = packet_len
                            
                        # Update average size
                        avg = self.dns_tracker[ip_src]['avg_size']
                        count = self.dns_tracker[ip_src]['response_count']
                        self.dns_tracker[ip_src]['avg_size'] = avg + (packet_len - avg) / count
                    
                    # Check amplification patterns
                    if self.dns_tracker[ip_src]['large_responses'] > 5:
                        # Multiple large responses in a short time
                        if current_time - self.dns_tracker[ip_src]['last_update'] < 10:
                            logging.warning(f"DNS amplification attack detected from {ip_src}. Multiple large responses in short time.")
                            return True
                        # Very large responses (over 4000 bytes)
                        if self.dns_tracker[ip_src]['max_size'] > 4000:
                            logging.warning(f"DNS amplification attack detected from {ip_src}. Very large DNS response: {self.dns_tracker[ip_src]['max_size']} bytes")
                            return True
                        # High average response size
                        if self.dns_tracker[ip_src]['avg_size'] > 2000:
                            logging.warning(f"DNS amplification attack detected from {ip_src}. High average response size: {int(self.dns_tracker[ip_src]['avg_size'])} bytes")
                            return True
                
            # Case 2: Check for DNS queries that could be used in amplification
            elif dst_port == 53:  # DNS query
                # Look for specific query types known for amplification
                if DNS in packet:
                    try:
                        qtype = packet[DNS].qd.qtype
                        # Check for query types commonly used in amplification attacks
                        if qtype in [15, 16, 255, 46]:  # MX, TXT, ANY, RRSIG records
                            # Track query by IP to detect query patterns
                            if ip_src not in self.dns_tracker:
                                self.dns_tracker[ip_src] = {
                                    'risky_queries': 1,
                                    'last_query': current_time,
                                    'query_types': {qtype: 1}
                                }
                            else:
                                self.dns_tracker[ip_src]['risky_queries'] = self.dns_tracker[ip_src].get('risky_queries', 0) + 1
                                self.dns_tracker[ip_src]['last_query'] = current_time
                                if 'query_types' not in self.dns_tracker[ip_src]:
                                    self.dns_tracker[ip_src]['query_types'] = {}
                                self.dns_tracker[ip_src]['query_types'][qtype] = self.dns_tracker[ip_src]['query_types'].get(qtype, 0) + 1
                            
                            # Detect if there's a high rate of risky queries
                            if self.dns_tracker[ip_src]['risky_queries'] > 10:
                                logging.warning(f"Potential DNS amplification attack detected from {ip_src}. Multiple high-risk queries.")
                                return True
                    except:
                        pass  # Sometimes DNS parsing can fail
        
        return False

    def check_fragment_attack(self, packet):
        """Advanced fragment attack detection"""
        if IP in packet:
            # Initialize fragment tracking if not exists
            if not hasattr(self, 'frag_tracker'):
                self.frag_tracker = {}
                
            # Get source IP and packet info
            ip_src = packet[IP].src
            ip_id = packet[IP].id
            frag = packet[IP].frag
            flags = packet[IP].flags
            pkt_len = len(packet)
            has_more_fragments = (flags & 1)  # MF flag
            current_time = time.time()
            
            # Create a fragment tracking key
            frag_key = f"{ip_src}_{ip_id}"
            
            # Attack pattern 1: Tiny fragment attack
            # Fragments smaller than 576 bytes (except the last one) are suspicious
            if has_more_fragments and pkt_len < 200:
                logging.warning(f"Tiny fragment detected from {ip_src}, ID: {ip_id}, length: {pkt_len}")
                return True
            
            # Track fragment info
            if frag_key not in self.frag_tracker:
                self.frag_tracker[frag_key] = {
                    'first_seen': current_time,
                    'fragments': {frag: {'offset': frag * 8, 'size': pkt_len, 'mf': has_more_fragments}},
                    'total_size': pkt_len,
                    'max_offset': frag * 8 + pkt_len,
                    'complete': not has_more_fragments and frag == 0
                }
            else:
                # Update tracker
                self.frag_tracker[frag_key]['fragments'][frag] = {
                    'offset': frag * 8, 
                    'size': pkt_len, 
                    'mf': has_more_fragments
                }
                self.frag_tracker[frag_key]['total_size'] += pkt_len
                
                # Update max offset
                max_offset = frag * 8 + pkt_len
                if max_offset > self.frag_tracker[frag_key]['max_offset']:
                    self.frag_tracker[frag_key]['max_offset'] = max_offset
                
                # Mark as complete if we received a fragment with MF=0 (last fragment)
                if not has_more_fragments:
                    self.frag_tracker[frag_key]['complete'] = True
                
                # Attack pattern 2: Fragment Overlap Attack
                # Check for overlapping fragments
                fragments = self.frag_tracker[frag_key]['fragments']
                for other_frag, info in fragments.items():
                    if other_frag != frag:  # Don't compare with self
                        other_start = info['offset']
                        other_end = other_start + info['size']
                        current_start = frag * 8
                        current_end = current_start + pkt_len
                        
                        # Check for overlap
                        if (current_start < other_end and current_end > other_start):
                            logging.warning(f"Fragment overlap attack detected from {ip_src}, ID: {ip_id}")
                            return True
                
                # Attack pattern 3: Fragment Flood
                # Too many fragments for a single packet
                if len(fragments) > 64:  # Typical max fragments should be much lower
                    logging.warning(f"Excessive fragments detected from {ip_src}, ID: {ip_id}, count: {len(fragments)}")
                    return True
                
                # Attack pattern 4: Timeout Attack
                # Incomplete fragments persisting for too long
                if not self.frag_tracker[frag_key].get('complete', False):
                    if current_time - self.frag_tracker[frag_key]['first_seen'] > 30:  # 30 sec timeout
                        logging.warning(f"Fragment timeout attack detected from {ip_src}, ID: {ip_id}")
                        return True
                
                # Attack pattern 5: Jumbo Fragment
                # Check for unreasonably large total size
                if self.frag_tracker[frag_key]['total_size'] > 65535:  # Max IP packet
                    logging.warning(f"Jumbo fragment attack detected from {ip_src}, ID: {ip_id}, size: {self.frag_tracker[frag_key]['total_size']}")
                    return True
                
            # Clean up old fragment trackers (do this occasionally)
            if hasattr(self, 'last_frag_cleanup') and current_time - getattr(self, 'last_frag_cleanup', 0) > 60:  # Every minute
                self.last_frag_cleanup = current_time
                expired_keys = []
                for key, data in self.frag_tracker.items():
                    if current_time - data['first_seen'] > 120:  # 2 minutes
                        expired_keys.append(key)
                
                for key in expired_keys:
                    del self.frag_tracker[key]
                
                logging.debug(f"Cleaned up {len(expired_keys)} expired fragment trackers")
                    
        return False

    def check_malformed_packet(self, packet):
        """Advanced malformed (corrupted/tampered) packet detection"""
        try:
            # Basic header checks
            if IP in packet:
                # Check for invalid IP header length
                if packet[IP].ihl * 4 > len(packet[IP]):
                    logging.warning(f"Malformed packet detected: Invalid IP header length from {packet[IP].src}")
                    return True
                
                # Check for unreasonable header length
                if packet[IP].ihl < 5 or packet[IP].ihl > 15:  # Valid IP header length is 5-15
                    logging.warning(f"Malformed packet detected: Unreasonable IP header length from {packet[IP].src}")
                    return True
                
                # Check for invalid IP length
                if packet[IP].len > len(packet):
                    logging.warning(f"Malformed packet detected: IP length mismatch from {packet[IP].src}")
                    return True
                
                # Check for invalid IP version
                if packet[IP].version != 4:
                    logging.warning(f"Malformed packet detected: Invalid IP version {packet[IP].version} from {packet[IP].src}")
                    return True
                    
                # Check for invalid IP flags
                if packet[IP].flags > 7:  # 3 bits only
                    logging.warning(f"Malformed packet detected: Invalid IP flags from {packet[IP].src}")
                    return True
                
                # TCP checks
                if TCP in packet:
                    # Check for invalid TCP header length
                    if packet[TCP].dataofs * 4 > len(packet[TCP]):
                        logging.warning(f"Malformed packet detected: Invalid TCP header length from {packet[IP].src}")
                        return True
                        
                    # Check for invalid TCP flags - some tools use invalid combination of flags
                    tcp_flags = packet[TCP].flags
                    # Check for all flags set (XMAS scan) or other suspicious combos
                    if tcp_flags == 0xFF or (tcp_flags & 0x17) == 0x17:  # FIN+PSH+URG set
                        logging.warning(f"Malformed packet detected: Suspicious TCP flags combination from {packet[IP].src}")
                        return True
                        
                    # Check for SYN+FIN (mutually exclusive)
                    if (tcp_flags & 0x03) == 0x03:  # SYN+FIN
                        logging.warning(f"Malformed packet detected: SYN+FIN flags from {packet[IP].src}")
                        return True
                        
                    # Check for invalid TCP options
                    if len(packet[TCP].options) > 40:
                        logging.warning(f"Malformed packet detected: Excessive TCP options from {packet[IP].src}")
                        return True
                    
                    # Check for invalid TCP sequence/ack numbers (potential DOS)
                    if packet[TCP].seq == 0 and packet[TCP].ack == 0 and tcp_flags != 0x02:  # Not just a SYN
                        logging.warning(f"Malformed packet detected: Zero seq/ack from {packet[IP].src}")
                        return True
                
                # UDP checks
                if UDP in packet:
                    # Check for invalid UDP length
                    if packet[UDP].len > len(packet[UDP]) or packet[UDP].len < 8:  # UDP header is 8 bytes
                        logging.warning(f"Malformed packet detected: Invalid UDP length from {packet[IP].src}")
                        return True
                    
                    # Check for NULL UDP checksum (often used in attacks)
                    if packet[UDP].chksum == 0 and not (packet[IP].src.startswith('127.') or packet[IP].dst.startswith('127.')):
                        logging.warning(f"Malformed packet detected: NULL UDP checksum from {packet[IP].src}")
                        return True
                
                # Fragment checks - fragment attacks
                if packet[IP].flags & 0x1 or packet[IP].frag > 0:  # More fragments or non-zero offset
                    # Track fragments to detect fragment attacks
                    frag_key = f"{packet[IP].id}_{packet[IP].src}_{packet[IP].dst}"
                    
                    # Check for tiny fragments
                    if len(packet[IP].payload) < 16:  # Extremely small fragments
                        logging.warning(f"Malformed packet detected: Tiny fragment from {packet[IP].src}")
                        return True
        except Exception as e:
            # Any error in parsing usually indicates malformed packet
            logging.warning(f"Exception in packet analysis, likely malformed: {str(e)}")
            return True
            
        return False

    def check_ip_spoofing(self, packet):
        """Advanced IP spoofing detection"""
        if not IP in packet:
            return False
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_ttl = packet[IP].ttl
        current_time = time.time()
        
        # Initialize spoofing detection trackers if they don't exist
        if not hasattr(self, 'spoofing_tracker'):
            self.spoofing_tracker = {}
            self.src_consistency = {}
            self.reserved_ips = [
                '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
                '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', 
                '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4',
                '240.0.0.0/4', '255.255.255.255/32'
            ]
            self.reserved_ip_networks = [ipaddress.ip_network(net) for net in self.reserved_ips]
            
        # Attack Pattern 1: Invalid Source IPs
        # Check for invalid source IPs such as broadcast, multicast, reserved addresses
        try:
            ip_obj = ipaddress.ip_address(src_ip)
            if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified or ip_obj.is_loopback:
                logging.warning(f"Spoofed packet detected: Invalid source IP {src_ip} (reserved/special)")
                return True
                
            # Check if source IP is in a reserved or bogon address space
            for net in self.reserved_ip_networks:
                if ip_obj in net and not self.is_local_network(src_ip):
                    # Skip if it's a legitimate local network address
                    if not (self.is_local_network(src_ip) and self.interface in ['lo', 'lo0']):
                        logging.warning(f"Spoofed packet detected: Source IP {src_ip} is in reserved network {net}")
                        return True
        except:
            # Invalid IP format
            logging.warning(f"Spoofed packet detected: Invalid IP format {src_ip}")
            return True
            
        # Attack Pattern 2: Impossible IP combinations
        # Check for impossible source-destination combinations
        if src_ip == dst_ip and not src_ip.startswith('127.'):
            logging.warning(f"Spoofed packet detected: Source and destination IP are identical: {src_ip}")
            return True
            
        # Attack Pattern 3: TTL-based spoofing detection
        # Track typical TTL values per source IP
        if src_ip not in self.src_consistency:
            self.src_consistency[src_ip] = {
                'first_seen': current_time,
                'ttl_values': [pkt_ttl],
                'ttl_count': {pkt_ttl: 1},
                'mac_addresses': set(),
                'last_packet': current_time
            }
            # If we have MAC information, record it
            if Ether in packet:
                self.src_consistency[src_ip]['mac_addresses'].add(packet[Ether].src)
        else:
            # Update TTL tracking
            profile = self.src_consistency[src_ip]
            profile['ttl_values'].append(pkt_ttl)
            profile['last_packet'] = current_time
            
            # Keep only the last 20 TTL values to avoid memory bloat
            if len(profile['ttl_values']) > 20:
                profile['ttl_values'] = profile['ttl_values'][-20:]
                
            # Update TTL count
            if pkt_ttl in profile['ttl_count']:
                profile['ttl_count'][pkt_ttl] += 1
            else:
                profile['ttl_count'][pkt_ttl] = 1
                
            # If we have MAC information, record it
            if Ether in packet:
                profile['mac_addresses'].add(packet[Ether].src)
                
            # Check for TTL anomalies
            if len(profile['ttl_values']) >= 5:  # Need some history for comparison
                ttl_values = profile['ttl_values'][-5:]
                dominant_ttl = max(profile['ttl_count'], key=profile['ttl_count'].get)
                
                # Calculate standard deviation of TTL values
                avg_ttl = sum(ttl_values) / len(ttl_values)
                variance = sum((x - avg_ttl) ** 2 for x in ttl_values) / len(ttl_values)
                std_dev = variance ** 0.5
                
                # Check for high TTL variance (which could indicate spoofing)
                # BUT exclude cases where TTL legitimately changes between OS updates
                if std_dev > 8 and len(profile['ttl_count']) > 3:
                    logging.warning(f"Spoofed packet detected: Highly variable TTL from {src_ip}, std dev: {std_dev:.2f}")
                    return True
                    
        # Attack Pattern 4: MAC-IP inconsistency
        # Check if a single IP address is coming from multiple MAC addresses
        # This typically shouldn't happen unless there's ARP spoofing or IP spoofing
        profile = self.src_consistency.get(src_ip, {})
        if profile and len(profile.get('mac_addresses', set())) > 3:
            logging.warning(f"Spoofed packet detected: IP {src_ip} seen with {len(profile['mac_addresses'])} different MAC addresses")
            return True
        
        # Attack Pattern 5: Local address from external interface
        # Private IPs shouldn't come from external interfaces
        if self.interface not in ['lo', 'lo0'] and not self.is_local_network(src_ip):
            try:
                ip_obj = ipaddress.ip_address(src_ip)
                if ip_obj.is_private:
                    logging.warning(f"Spoofed packet detected: Private IP {src_ip} from external interface")
                    return True
            except:
                pass
            
        # Clean up old entries every 10 minutes
        if hasattr(self, 'last_spoofing_cleanup') and current_time - getattr(self, 'last_spoofing_cleanup', 0) > 600:
            self.last_spoofing_cleanup = current_time
            expired_keys = []
            for key, data in self.src_consistency.items():
                if current_time - data['last_packet'] > 3600:  # 1 hour
                    expired_keys.append(key)
                    
            for key in expired_keys:
                del self.src_consistency[key]
                
            logging.debug(f"Cleaned up {len(expired_keys)} expired IP spoofing tracking entries")
        
        return False

    def check_ttl_anomalies(self, packet):
        """Enhanced detection of TTL anomalies"""
        if IP in packet:
            ttl = packet[IP].ttl
            ip_src = packet[IP].src
            
            # Normal TTL ranges by OS
            # Windows: Usually 128 or 64
            # Linux/Unix: Usually 64
            # Network equipment (routers): Usually 255
            
            # Track TTL values by IP to detect inconsistencies
            if ip_src not in self.ttl_tracker:
                self.ttl_tracker[ip_src] = {'values': [ttl], 'last_update': time.time()}
            else:
                self.ttl_tracker[ip_src]['values'].append(ttl)
                self.ttl_tracker[ip_src]['last_update'] = time.time()
                
                # Keep only the last 10 values
                if len(self.ttl_tracker[ip_src]['values']) > 10:
                    self.ttl_tracker[ip_src]['values'] = self.ttl_tracker[ip_src]['values'][-10:]
                
                # Check for TTL inconsistency within the same IP
                ttl_values = self.ttl_tracker[ip_src]['values']
                if len(ttl_values) > 3:  # Only check if we have enough samples
                    # Calculate the standard deviation of TTL values
                    avg = sum(ttl_values) / len(ttl_values)
                    variance = sum((x - avg) ** 2 for x in ttl_values) / len(ttl_values)
                    std_dev = variance ** 0.5
                    
                    # Significant TTL variations may indicate IP spoofing or TTL manipulation
                    if std_dev > 5 and max(ttl_values) - min(ttl_values) > 10:
                        logging.warning(f"TTL anomaly detected from {ip_src}: inconsistent TTL values {ttl_values}")
                        return True
            
            # Detect extremely low or high TTL values
            if ttl < 5 or ttl > 250:
                return True
                
        return False

    def check_tcp_sequence_prediction(self, packet):
        """Enhanced check for TCP sequence prediction attacks"""
        if TCP in packet:
            seq = packet[TCP].seq
            ip_src = packet[IP].src
            
            # Using lock to prevent race conditions on sequence tracking
            with self.tcp_flags_lock:
                # Initialize sequence tracker for this IP if it doesn't exist
                if not hasattr(self, 'seq_tracker'):
                    self.seq_tracker = {}
                    
                if ip_src not in self.seq_tracker:
                    self.seq_tracker[ip_src] = {
                        'sequences': [seq],
                        'last_update': time.time(),
                        'prediction_attempts': 0
                    }
                else:
                    # Add new sequence
                    self.seq_tracker[ip_src]['sequences'].append(seq)
                    self.seq_tracker[ip_src]['last_update'] = time.time()
                    
                    # Keep only the most recent sequences (limited to 8)
                    if len(self.seq_tracker[ip_src]['sequences']) > 8:
                        self.seq_tracker[ip_src]['sequences'] = self.seq_tracker[ip_src]['sequences'][-8:]
                    
                    # Check for predictable sequence patterns
                    sequences = self.seq_tracker[ip_src]['sequences']
                    if len(sequences) >= 3:
                        # Check for linear progression
                        diffs = [sequences[i+1] - sequences[i] for i in range(len(sequences)-1)]
                        
                        # If we have consistent differences (potential linear sequence pattern)
                        if len(set(diffs)) <= 2 and len(diffs) >= 3:
                            self.seq_tracker[ip_src]['prediction_attempts'] += 1
                            logging.warning(f"Potential TCP sequence prediction attack from {ip_src}")
                            return True
                        
                        # Check for simple incremental patterns (like seq+1)
                        if all(d == 1 for d in diffs):
                            self.seq_tracker[ip_src]['prediction_attempts'] += 1
                            logging.warning(f"Simple TCP sequence pattern detected from {ip_src}")
                            return True
                        
                        # Check for numerically close patterns
                        if all(0 < d < 100 for d in diffs):
                            self.seq_tracker[ip_src]['prediction_attempts'] += 1
                            logging.warning(f"Suspicious TCP sequence proximity from {ip_src}")
                            return True
                
                # Basic checks for obviously bad sequences
                if seq == 0 or seq == 1:
                    return True
                
        return False

    def safe_clean_dictionary(self, dictionary, timestamp_key, lock=None, cutoff=None, 
                              max_size=5000, popitem_last=False):
        """Safely clean a dictionary by removing old entries and limiting size
        
        Args:
            dictionary: Dictionary to clean
            timestamp_key: Key within dictionary entries that contains the timestamp value
            lock: Optional lock to use for thread safety
            cutoff: Timestamp cutoff value. If None, uses current time - 1 hour
            max_size: Maximum size of dictionary
            popitem_last: Whether to remove newest (True) or oldest (False) items when limiting size
        """
        # Use current time if cutoff not provided
        if cutoff is None:
            current_time = time.time()
            cutoff = current_time - 3600  # Default 1 hour cutoff
            
        if dictionary is None or not isinstance(dictionary, dict):
            logging.debug("Skipping cleanup for non-dictionary object")
            return
            
        # Get the proper lock if none provided
        if lock is None:
            if dictionary is self.connection_tracker:
                lock = self.connection_lock
            elif dictionary is self.packet_rates:
                lock = self.packet_rates_lock
            elif dictionary is getattr(self, 'tcp_flags_tracker', None):
                lock = getattr(self, 'tcp_flags_lock', None) 
            elif dictionary is getattr(self, 'fragment_tracker', None):
                lock = getattr(self, 'fragment_lock', None)
                
        # Use nullcontext if no lock available
        context_mgr = lock if lock is not None else nullcontext()
        
        try:
            with context_mgr:
                # First pass: remove invalid entries and expired entries
                keys_to_remove = []
                # Get all keys first to avoid modification during iteration
                keys = list(dictionary.keys())
                
                for key in keys:
                    if key is None:
                        keys_to_remove.append(key)
                        continue
                        
                    try:
                        # Entry must exist and be a dictionary
                        entry = dictionary.get(key)
                        if entry is None or not isinstance(entry, dict):
                            keys_to_remove.append(key)
                            continue
                            
                        # Entry must have timestamp key
                        if timestamp_key not in entry:
                            logging.debug(f"Missing {timestamp_key} for {key} in dictionary, removing entry")
                            keys_to_remove.append(key)
                            continue
                            
                        # Timestamp must be a valid number
                        timestamp = entry.get(timestamp_key)
                        if timestamp is None or not isinstance(timestamp, (int, float)):
                            logging.debug(f"Invalid timestamp for {key}: {timestamp}")
                            keys_to_remove.append(key)
                            continue
                            
                        # Check if entry is too old
                        if timestamp < cutoff:
                            # Special case for attack sources with blocked flag
                            if dictionary is getattr(self, 'attack_sources', {}) and entry.get('blocked', False):
                                if timestamp < (cutoff - 86400):  # 24 hours older than normal cutoff
                                    keys_to_remove.append(key)
                            else:
                                keys_to_remove.append(key)
                    except Exception as e:
                        logging.debug(f"Error checking dictionary entry {key}: {str(e)}")
                        keys_to_remove.append(key)
                        
                # Safe removal of invalid/expired entries
                for key in keys_to_remove:
                    try:
                        dictionary.pop(key, None)
                    except Exception as e:
                        logging.debug(f"Error removing key {key}: {str(e)}")
                        
                # Second pass: limit dictionary size if still too large
                if len(dictionary) > max_size:
                    logging.debug(f"Dictionary size {len(dictionary)} exceeds limit {max_size}, trimming")
                    try:
                        # For timestamp-based dictionaries, we can sort by timestamp
                        sorted_items = []
                        for key, value in dictionary.items():
                            try:
                                if isinstance(value, dict) and timestamp_key in value:
                                    timestamp = value[timestamp_key]
                                    if isinstance(timestamp, (int, float)):
                                        sorted_items.append((key, timestamp))
                            except Exception:
                                pass
                                
                        if sorted_items:
                            # Sort by timestamp (oldest first)
                            sorted_items.sort(key=lambda x: x[1])
                            # Remove oldest entries until we're under the limit
                            to_remove = len(dictionary) - max_size
                            for i in range(min(to_remove, len(sorted_items))):
                                try:
                                    dictionary.pop(sorted_items[i][0], None)
                                except Exception:
                                    pass
                    except Exception as e:
                        logging.debug(f"Error during size limiting: {str(e)}")
        except Exception as e:
            logging.error(f"Error during dictionary cleanup: {str(e)}")
    
    def cleanup_old_data(self, current_time=None):
        """Clean up old data from all tracking dictionaries using safe methods.
        
        Args:
            current_time: Current timestamp, will use time.time() if None
        """
        if current_time is None:
            current_time = time.time()
            
        # Update attack statistics before cleanup
        try:
            with self.stats_lock:
                # Calculate active threats
                active_threats = 0
                
                # Count active SYN flood attacks
                for key, data in self.syn_tracker.items():
                    if current_time - data['first_seen'] <= self.syn_flood_timeout and data['count'] >= self.syn_flood_threshold:
                        active_threats += 1
                
                # Count active port scan attacks
                for src_ip, data in self.port_scan_tracker.items():
                    for dst_ip, ports in data['targets'].items():
                        if len(ports) >= self.port_scan_threshold and current_time - data['first_seen'] <= self.port_scan_timeout:
                            active_threats += 1
                            break
                
                # Count active UDP flood attacks
                for key, data in self.udp_flood_tracker.items():
                    if current_time - data['first_seen'] <= self.udp_flood_timeout and data['count'] >= self.udp_flood_threshold:
                        active_threats += 1
                
                # Count active ICMP flood attacks
                for key, data in self.icmp_flood_tracker.items():
                    if current_time - data['first_seen'] <= self.icmp_flood_timeout and data['count'] >= self.icmp_flood_threshold:
                        active_threats += 1
                
                # Count active fragmentation attacks
                for src_ip, data in self.frag_tracker.items():
                    if current_time - data['first_seen'] <= self.frag_timeout and data['count'] >= self.frag_threshold:
                        active_threats += 1
                
                # Update active threats count
                self.stats['active_threats'] = active_threats
                
                # Update blocking statistics
                if hasattr(self, 'blocked_ips'):
                    self.stats['blocked_ips_count'] = len(self.blocked_ips)
        except Exception as e:
            logging.error(f"Error updating attack statistics: {str(e)}")
            # Continue with cleanup even if stats update fails
            
        try:
            logging.debug("Starting dictionary cleanup process")
            
            # Calculate cutoff times once
            cutoff_time = current_time - 3600  # Remove data older than 1 hour
            attack_cutoff = current_time - 14400  # 4 hours for attack sources
            max_entries = 5000  # Max entries for standard trackers
            attack_max_entries = 10000  # Max entries for attack history
            
            # 1. Clean up connection tracker
            if hasattr(self, 'connection_tracker'):
                self.safe_clean_dictionary(self.connection_tracker, 'last_seen', 
                                       self.connection_lock, cutoff_time, max_entries)
            
            # 2. Clean up packet rates
            if hasattr(self, 'packet_rates'):
                self.safe_clean_dictionary(self.packet_rates, 'timestamp', 
                                       self.packet_rates_lock, cutoff_time, max_entries)
                                   
            # 3. Clean up TCP flags
            if hasattr(self, 'tcp_flags_tracker'):
                self.safe_clean_dictionary(self.tcp_flags_tracker, 'last_seen', 
                                       self.tcp_flags_lock, cutoff_time, max_entries)
                                   
            # 4. Clean up various attack trackers with proper timestamp keys
            with self.stats_lock:  # Use stats lock for these trackers
                # SYN flood tracker
                if hasattr(self, 'syn_tracker'):
                    self.safe_clean_dictionary(self.syn_tracker, 'timestamp', None, cutoff_time, max_entries)
                
                # UDP flood tracker
                if hasattr(self, 'udp_tracker'):
                    self.safe_clean_dictionary(self.udp_tracker, 'timestamp', None, cutoff_time, max_entries)
                
                # ICMP flood tracker
                if hasattr(self, 'icmp_tracker'):
                    self.safe_clean_dictionary(self.icmp_tracker, 'timestamp', None, cutoff_time, max_entries)
                
                # Port scan tracker
                if hasattr(self, 'port_scan_tracker'):
                    self.safe_clean_dictionary(self.port_scan_tracker, 'timestamp', None, cutoff_time, max_entries)
            
            # 5. Clean up TCP-specific trackers with tcp_flags_lock
            if hasattr(self, 'seq_tracker'):
                self.safe_clean_dictionary(self.seq_tracker, 'timestamp', self.tcp_flags_lock, cutoff_time, max_entries)
            
            # 6. Clean up fragment tracker with its own lock
            if hasattr(self, 'fragment_tracker'):
                self.safe_clean_dictionary(self.fragment_tracker, 'timestamp', self.fragment_lock, cutoff_time, max_entries)
            
            # 7. Special case: Clean attack_sources with longer retention
            if hasattr(self, 'attack_sources'):
                self.safe_clean_dictionary(self.attack_sources, 'last_attack', 
                                       self.stats_lock, attack_cutoff, attack_max_entries)
                
        except Exception as e:
            logging.error(f"Error during cleanup_old_data: {str(e)}")
            # Continue execution to avoid crashing the entire application
            
            # Log memory usage statistics periodically
            logging.info(f"Memory cleanup performed: {len(self.syn_tracker) if hasattr(self, 'syn_tracker') else 0} SYN entries, "
                        f"{len(self.udp_tracker) if hasattr(self, 'udp_tracker') else 0} UDP entries")
                
        except Exception as e:
            logging.error(f"Error in cleanup_old_data: {str(e)}")
            # Continue operation despite cleanup errors
    
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

    def packet_handler(self, packet):
        """Process each captured packet
        This is called by Scapy's sniff function for each packet captured"""
        try:
            # Increment the packet counter - fixes the total_packets always 0 issue
            with self.stats_lock:
                self.stats['total_packets'] += 1
                
                # Log every 1000 packets just to verify capture is working
                if self.stats['total_packets'] % 1000 == 0:
                    logging.info(f"Processed {self.stats['total_packets']} packets")
            
            # Even with advanced protection, only fully process a percentage of packets
            # This drastically improves performance while still maintaining security
            sample_rate = 0.1  # Process only 10% of packets in detail
            
            # Basic checks for all packets - very fast
            if hasattr(packet, 'src') and packet.haslayer('IP'):
                src_ip = packet.getlayer('IP').src
                # Check if IP is in blacklist (fast check)
                if src_ip in getattr(self, 'blacklist', []):
                    with self.stats_lock:
                        self.stats['blocked_packets'] += 1
                    return  # Skip further processing for blocked IPs
            
            # Sample a percentage of packets for detailed analysis
            if random.random() < sample_rate and hasattr(self, 'advanced_protection') and self.advanced_protection:
                # Use minimal processing for most packets
                if hasattr(self, 'packet_executor') and self.packet_executor:
                    try:
                        # Submit with low priority - don't block the queue
                        self.packet_executor.submit(self._process_packet, packet) 
                    except Exception:
                        pass  # Silently continue if thread pool is full
            
        except Exception as e:
            # Just log and continue to avoid blocking packet processing
            logging.debug(f"Error in packet_handler: {str(e)}")
            pass  # Never block the main packet capture thread
    
    def _process_packet_minimal(self, packet):
        """Lightweight packet processing for better performance"""
        try:
            # Only do very basic checks for blacklisted IPs
            if hasattr(packet, 'src') and packet.haslayer('IP'):
                src_ip = packet.getlayer('IP').src
                if src_ip in getattr(self, 'blacklist', []):
                    with self.stats_lock:
                        self.stats['blocked_packets'] += 1
        except Exception as e:
            # Just log and continue - don't stop processing
            logging.debug(f"Error in minimal packet processing: {str(e)}")
    
    def start_protection(self):
        if not self.interface:
            logging.error("No interface specified for packet capture!")
            return False
            
        # Check if interface exists before starting
        if not self.check_interface_exists():
            logging.error(f"Interface {self.interface} does not exist or is not up!")
            return False
            
        # Initialize thread pool for parallel packet processing if not already done
        if not hasattr(self, 'thread_pool'):
            self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.worker_threads)
            logging.info(f"Initialized thread pool with {self.worker_threads} workers")
            
        # Start Scapy sniffer in a separate thread so it doesn't block
        self.stop_sniffing = False
        self.sniffer_thread = threading.Thread(target=self._run_sniffer)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        
        logging.info(f"Started protection on interface {self.interface}")
        return True
    def _run_sniffer(self):
        """Run the packet sniffer in a separate thread"""
        try:
            # Optimized sniff parameters for performance
            sniff(iface=self.interface, prn=self.packet_handler, store=0, 
                  filter="ip", stop_filter=lambda p: self.stop_sniffing)
        except Exception as e:
            logging.error(f"Sniffer error: {str(e)}")

    def check_interface_exists(self):
        """Check if specified interface exists on the system"""
        try:
            if platform.system() == "Windows":
                # Windows implementation
                output = subprocess.check_output("ipconfig /all", shell=True).decode("utf-8")
                return self.interface in output
            else:
                # Linux/Unix implementation
                interfaces = get_if_list()
                return self.interface in interfaces
        except Exception as e:
            logging.error(f"Error checking interface: {str(e)}")
            return False

    def stop_protection(self):
        """Stop the packet sniffer"""
        self.stop_sniffing = True
        if hasattr(self, 'sniffer_thread') and self.sniffer_thread is not None:
            self.sniffer_thread.join(timeout=2.0)
            logging.info("Protection stopped")
        return True

    def block_ip(self, ip, reason):
        """Block an IP address that has been detected as malicious"""
        with self.blacklist_lock:
            if ip not in self.blacklist:
                self.blacklist.append(ip)
                
                # Log the blocking action
                logging.warning(f"BLOCKED IP: {ip} - Reason: {reason}")
                
                # Track blocking statistics
                with self.stats_lock:
                    if 'ips_blocked' not in self.stats:
                        self.stats['ips_blocked'] = 0
                    self.stats['ips_blocked'] += 1
                    
    def __str__(self):
        """Return string representation with statistics"""
        result = [f"OpenMammoth v{self.VERSION}"]
        
        # Add basic stats
        with self.stats_lock:
            for key, value in self.stats.items():
                result.append(f"{key}: {value}")
                
        return "\n".join(result)
    def is_suspicious_ip_pattern(self, ip_address):
        """Check if an IP matches suspicious patterns (e.g., known botnets)"""
        try:
            # Check if IP is in common botnet ranges
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Convert to int for faster comparison
            ip_int = int(ip_obj)
            
            # Check against known bad IP ranges (example ranges)
            suspicious_ranges = [
                (ipaddress.ip_network('185.156.73.0/24'), 'DDoS botnet'),
                (ipaddress.ip_network('5.188.86.0/24'), 'Scanning network'),
                # Add more ranges as needed
            ]
            
            for net, reason in suspicious_ranges:
                if ip_obj in net:
                    logging.warning(f"IP {ip_address} matched suspicious range {net} ({reason})")
                    return True
                    
            return False
            
        except Exception as e:
            logging.error(f"Error checking IP pattern: {str(e)}")
            return False
    def cleanup_old_data(self):
        """Clean up old data in tracking dictionaries to prevent memory growth"""
        current_time = time.time()
        
        try:
            # Clean SYN tracker
            with self.syn_lock:
                self._clean_tracker(self.syn_tracker, self.syn_flood_timeout, current_time)
                
            # Clean UDP tracker
            with self.udp_lock:
                self._clean_tracker(self.udp_flood_tracker, self.udp_flood_timeout, current_time)
                
            # Clean port scan tracker
            with self.port_scan_lock:
                self._clean_tracker(self.port_scan_tracker, self.port_scan_timeout, current_time)
            # Clean attack sources
            keys_to_remove = []
            current_time = time.time()
            
            with self.attack_sources_lock:
                for ip, data in self.attack_sources.items():
                    if current_time - data['timestamp'] > self.attack_timeout:
                        keys_to_remove.append(ip)
                
                for ip in keys_to_remove:
                    del self.attack_sources[ip]
                    
        except Exception as e:
            logging.error(f"Error in cleanup_old_data: {str(e)}")
            
    def _clean_tracker(self, tracker, timeout, current_time):
        """Helper method to clean old entries from trackers"""
        keys_to_remove = []
        
        # Identify keys to remove
        for key, data in tracker.items():
            if 'first_seen' in data and current_time - data['first_seen'] > timeout:
                keys_to_remove.append(key)
                
        # Remove the keys
        for key in keys_to_remove:
            del tracker[key]
            
    def _process_packet(self, packet):
        """Process a packet for attack detection"""
        try:
            # Increment total packet count
            with self.stats_lock:
                if 'total_packets' not in self.stats:
                    self.stats['total_packets'] = 0
                self.stats['total_packets'] += 1
                
            # Get current timestamp
            current_time = time.time()
            
            # Skip processing if it's a blacklisted IP
            if self.is_blacklisted_ip(packet):
                return
                
            # Check if IP is in a suspicious pattern range
            if packet.haslayer('IP'):
                src_ip = packet.getlayer('IP').src
                if self.is_suspicious_ip_pattern(src_ip):
                    self.block_ip(src_ip, "Matched suspicious IP pattern")
                    return
                    
            # Perform advanced analysis if enabled
            if self.protection_level >= 3 and random.random() > 0.1:
                # Skip detailed analysis of 90% of packets in advanced mode for performance
                return
            
            # ================ ICMP FLOOD DETECTION ================
            if packet.haslayer('ICMP'):
                icmp = packet.getlayer('ICMP')
                ip = packet.getlayer('IP')
                
                # Extract source and destination information
                src_ip = ip.src
                dst_ip = ip.dst
                
                # Track ICMP packets for flood detection (per destination IP)
                key = dst_ip
                
                with self.icmp_lock:
                    # Create entry if it doesn't exist
                    if key not in self.icmp_flood_tracker:
                        self.icmp_flood_tracker[key] = {'count': 0, 'sources': {}, 'first_seen': current_time}
                    
                    # Increment counters
                    self.icmp_flood_tracker[key]['count'] += 1
                    
                    # Track each unique source
                    if src_ip not in self.icmp_flood_tracker[key]['sources']:
                        self.icmp_flood_tracker[key]['sources'][src_ip] = 0
                    self.icmp_flood_tracker[key]['sources'][src_ip] += 1
                    
                    # Check for ICMP flood conditions
                    time_window = current_time - self.icmp_flood_tracker[key]['first_seen']
                    if (time_window <= self.icmp_flood_timeout and 
                            self.icmp_flood_tracker[key]['count'] >= self.icmp_flood_threshold):
                        
                        # Alert for ICMP flood (limit alert frequency)
                        alert_key = f"icmpflood_{key}"
                        if (alert_key not in self.last_alert_time or 
                                current_time - self.last_alert_time[alert_key] > self.flood_alerting_interval):
                            
                            # Log the detection
                            source_count = len(self.icmp_flood_tracker[key]['sources'])
                            logging.warning(
                                f"ICMP FLOOD DETECTED: {self.icmp_flood_tracker[key]['count']} ICMP packets " +
                                f"to {dst_ip} from {source_count} sources in {time_window:.2f}s")
                            
                            # Update last alert time
                            self.last_alert_time[alert_key] = current_time
                            
                            # Increment detection statistics
                            with self.stats_lock:
                                if 'icmp_flood_detected' not in self.stats:
                                    self.stats['icmp_flood_detected'] = 0
                                self.stats['icmp_flood_detected'] += 1
                            
                            # For severe attacks, consider blocking top sources
                            if self.icmp_flood_tracker[key]['count'] > self.icmp_flood_threshold * 2:
                                # Find the top offending sources
                                top_sources = sorted(
                                    self.icmp_flood_tracker[key]['sources'].items(), 
                                    key=lambda x: x[1], 
                                    reverse=True
                                )[:3]  # Top 3 sources
                                
                                # Block these sources
                                for attack_src, count in top_sources:
                                    logging.warning(f"Blocking {attack_src} for ICMP flood attack ({count} packets)")
                                    self.block_ip(attack_src, "ICMP flood attack")
                                    
            # ================ TCP FLAGS MANIPULATION DETECTION ================
            # This detects unusual TCP flag combinations that could indicate scanning or manipulation
            if packet.haslayer('TCP'):
                tcp = packet.getlayer('TCP')
                ip = packet.getlayer('IP')
                src_ip = ip.src
                
                # Detect unusual flag combinations (e.g., FIN-PSH-URG without ACK, known as XMAS scan)
                if tcp.flags & 0x29 == 0x29 and not (tcp.flags & 0x10):  # FIN-PSH-URG without ACK
                    logging.warning(f"XMAS scan detected from {src_ip}")
                    self.block_ip(src_ip, "XMAS scan detected")
                    
                    # Increment detection statistics
                    with self.stats_lock:
                        if 'xmas_scan_detected' not in self.stats:
                            self.stats['xmas_scan_detected'] = 0
                        self.stats['xmas_scan_detected'] += 1
                        
                # Detect NULL scan (no flags set)
                elif tcp.flags == 0:
                    logging.warning(f"NULL scan detected from {src_ip}")
                    self.block_ip(src_ip, "NULL scan detected")
                    
                    # Increment detection statistics
                    with self.stats_lock:
                        if 'null_scan_detected' not in self.stats:
                            self.stats['null_scan_detected'] = 0
                        self.stats['null_scan_detected'] += 1
                        
                # Detect FIN scan (only FIN flag set)
                elif tcp.flags == 0x01:
                    logging.warning(f"FIN scan detected from {src_ip}")
                    self.block_ip(src_ip, "FIN scan detected")
                    
                    # Increment detection statistics
                    with self.stats_lock:
                        if 'fin_scan_detected' not in self.stats:
                            self.stats['fin_scan_detected'] = 0
                        self.stats['fin_scan_detected'] += 1
            
            # ================ IP FRAGMENTATION ATTACK DETECTION ================
            # This detects potential IP fragmentation based DoS or evasion attacks
            if packet.haslayer('IP'):
                ip = packet.getlayer('IP')
                src_ip = ip.src
                
                # Check if packet is fragmented
                is_fragment = (ip.flags == 1) or (ip.frag > 0)  # MF flag or fragment offset > 0
                
                if is_fragment:
                    with self.frag_lock:
                        # Track fragmented packets per source IP
                        if src_ip not in self.frag_tracker:
                            self.frag_tracker[src_ip] = {'count': 0, 'first_seen': current_time}
                        
                        # Increment counter
                        self.frag_tracker[src_ip]['count'] += 1
                        
                        # Check if we exceed threshold in specified time window
                        time_window = current_time - self.frag_tracker[src_ip]['first_seen']
                        if (time_window <= self.frag_timeout and 
                                self.frag_tracker[src_ip]['count'] >= self.frag_threshold):
                                
                            # Alert for fragmentation attack (limit alert frequency)
                            alert_key = f"frag_{src_ip}"
                            if (alert_key not in self.last_alert_time or 
                                    current_time - self.last_alert_time[alert_key] > self.flood_alerting_interval):
                                
                                # Log the detection
                                logging.warning(
                                    f"FRAGMENTATION ATTACK DETECTED: {self.frag_tracker[src_ip]['count']} " +
                                    f"fragmented packets from {src_ip} in {time_window:.2f}s")
                                
                                # Update last alert time
                                self.last_alert_time[alert_key] = current_time
                                
                                # Increment detection statistics
                                with self.stats_lock:
                                    if 'frag_attack_detected' not in self.stats:
                                        self.stats['frag_attack_detected'] = 0
                                    self.stats['frag_attack_detected'] += 1
                                
                                # Block for severe attacks
                                if self.frag_tracker[src_ip]['count'] > self.frag_threshold * 2:
                                    logging.warning(f"Blocking {src_ip} for fragmentation attack")
                                    self.block_ip(src_ip, "Fragmentation attack")

            # ================ ARP SPOOF DETECTION ================
            # This detects ARP spoofing attacks by tracking MAC-IP mappings
            if packet.haslayer('ARP'):
                arp = packet.getlayer('ARP')
                
                # Only process ARP responses (is-at, who-has)
                if arp.op == 2:  # is-at (ARP reply)
                    ip_addr = arp.psrc  # Source IP
                    mac_addr = arp.hwsrc  # Source MAC
                    
                    with self.arp_lock:
                        # If we don't have this IP in our tracker yet
                        if ip_addr not in self.arp_tracker:
                            self.arp_tracker[ip_addr] = {
                                'macs': {mac_addr: 1},
                                'first_seen': current_time,
                                'count': 1
                            }
                        else:
                            # Increment counter for this IP
                            self.arp_tracker[ip_addr]['count'] += 1
                            
                            # Check if this MAC is already associated with this IP
                            if mac_addr in self.arp_tracker[ip_addr]['macs']:
                                self.arp_tracker[ip_addr]['macs'][mac_addr] += 1
                            else:
                                # New MAC claiming to be this IP - potential spoofing
                                self.arp_tracker[ip_addr]['macs'][mac_addr] = 1
                                
                                # If we've seen multiple MACs for this IP, that's suspicious
                                if len(self.arp_tracker[ip_addr]['macs']) >= self.arp_threshold:
                                    # Alert for ARP spoofing
                                    alert_key = f"arp_{ip_addr}"
                                    if (alert_key not in self.last_alert_time or 
                                            current_time - self.last_alert_time[alert_key] > self.flood_alerting_interval):
                                        
                                        # Get all MACs for this IP
                                        all_macs = list(self.arp_tracker[ip_addr]['macs'].keys())
                                        mac_list_str = ", ".join(all_macs)
                                        
                                        # Log the detection
                                        logging.warning(
                                            f"ARP SPOOFING DETECTED: IP {ip_addr} claimed by {len(all_macs)} different MACs: {mac_list_str}")
                                        
                                        # Update last alert time
                                        self.last_alert_time[alert_key] = current_time
                                        
                                        # Increment detection statistics
                                        with self.stats_lock:
                                            if 'arp_spoof_detected' not in self.stats:
                                                self.stats['arp_spoof_detected'] = 0
                                            self.stats['arp_spoof_detected'] += 1
                                        
                                        # We don't block here since the IP might be legitimate
                                        # Instead, we alert the administrator about the suspicious activity
                                        print(f"{Fore.RED}[ALERT] ARP SPOOFING: {ip_addr} claimed by multiple MAC addresses!{Style.RESET_ALL}")
                                        
            # ================ TTL ANOMALY DETECTION ================
            # This detects unusual TTL values which could indicate spoofing or evasion
            if packet.haslayer('IP'):
                ip = packet.getlayer('IP')
                src_ip = ip.src
                ttl = ip.ttl
                
                with self.ttl_lock:
                    # Track TTL values per source IP
                    if src_ip not in self.ttl_tracker:
                        self.ttl_tracker[src_ip] = {'ttls': set(), 'count': 0, 'first_seen': current_time}
                    
                    # Add this TTL to the set and increment counter
                    self.ttl_tracker[src_ip]['ttls'].add(ttl)
                    self.ttl_tracker[src_ip]['count'] += 1
                    
                    # If we've seen many packets and multiple different TTL values, this is suspicious
                    if (self.ttl_tracker[src_ip]['count'] > self.ttl_anomaly_threshold and 
                            len(self.ttl_tracker[src_ip]['ttls']) > 2):
                        
                        # Alert for TTL anomaly (limit alert frequency)
                        alert_key = f"ttl_{src_ip}"
                        if (alert_key not in self.last_alert_time or 
                                current_time - self.last_alert_time[alert_key] > self.flood_alerting_interval):
                            
                            # Log the detection
                            ttl_values = ", ".join(str(t) for t in self.ttl_tracker[src_ip]['ttls'])
                            logging.warning(
                                f"TTL ANOMALY DETECTED: {src_ip} using multiple TTL values: {ttl_values} " +
                                f"in {self.ttl_tracker[src_ip]['count']} packets")
                            
                            # Update last alert time
                            self.last_alert_time[alert_key] = current_time
                            
                            # Increment detection statistics
                            with self.stats_lock:
                                if 'ttl_anomaly_detected' not in self.stats:
                                    self.stats['ttl_anomaly_detected'] = 0
                                self.stats['ttl_anomaly_detected'] += 1
                            
                            # Consider this highly suspicious - could be IP spoofing
                            if len(self.ttl_tracker[src_ip]['ttls']) > 3:
                                logging.warning(f"Blocking {src_ip} for suspicious TTL anomaly (possible spoofing)")
                                self.block_ip(src_ip, "TTL anomaly (possible spoofing)")
                                
            # ================ DNS AMPLIFICATION DETECTION ================
            # This detects potential DNS amplification attacks (large responses that could be used for reflection)
            if packet.haslayer('DNS') and packet.haslayer('UDP'):
                dns = packet.getlayer('DNS')
                ip = packet.getlayer('IP')
                udp = packet.getlayer('UDP')
                
                # We're interested in DNS responses (QR=1)
                if dns.qr == 1:  # This is a response
                    src_ip = ip.src
                    dst_ip = ip.dst
                    src_port = udp.sport
                    dst_port = udp.dport
                    packet_size = len(packet)
                    
                    # Track large DNS responses (potential amplification)
                    if packet_size >= self.dns_amp_size:
                        with self.dns_lock:
                            # Key is the source of the large response
                            key = f"{src_ip}:{src_port}"
                            
                            if key not in self.dns_tracker:
                                self.dns_tracker[key] = {
                                    'count': 0, 
                                    'bytes': 0,
                                    'first_seen': current_time,
                                    'targets': {}
                                }
                            
                            # Increment counters
                            self.dns_tracker[key]['count'] += 1
                            self.dns_tracker[key]['bytes'] += packet_size
                            
                            # Track targets
                            if dst_ip not in self.dns_tracker[key]['targets']:
                                self.dns_tracker[key]['targets'][dst_ip] = 0
                            self.dns_tracker[key]['targets'][dst_ip] += 1
                            
                            # Check if this might be an amplification attack
                            time_window = current_time - self.dns_tracker[key]['first_seen']
                            if (time_window <= self.dns_amp_timeout and 
                                    self.dns_tracker[key]['count'] >= self.dns_amp_threshold):
                                
                                # Check if we have a high amplification factor (many bytes)
                                avg_response_size = self.dns_tracker[key]['bytes'] / self.dns_tracker[key]['count']
                                
                                # Alert for potential DNS amplification
                                alert_key = f"dns_amp_{src_ip}"
                                if (alert_key not in self.last_alert_time or 
                                        current_time - self.last_alert_time[alert_key] > self.flood_alerting_interval):
                                    
                                    # Additional check: if multiple targets, more likely to be an attack
                                    target_count = len(self.dns_tracker[key]['targets'])
                                    
                                    # Log the detection
                                    logging.warning(
                                        f"DNS AMPLIFICATION DETECTED: {self.dns_tracker[key]['count']} large responses " +
                                        f"from {src_ip}:{src_port} totaling {self.dns_tracker[key]['bytes']/1024:.2f} KB " +
                                        f"(avg {avg_response_size:.2f} bytes) to {target_count} targets in {time_window:.2f}s")
                                    
                                    # Update last alert time
                                    self.last_alert_time[alert_key] = current_time
                                    
                                    # Increment detection statistics
                                    with self.stats_lock:
                                        if 'dns_amp_detected' not in self.stats:
                                            self.stats['dns_amp_detected'] = 0
                                        self.stats['dns_amp_detected'] += 1
                                    
                                    # If very severe (many targets and high byte count), consider blocking
                                    if target_count > 3 and self.dns_tracker[key]['bytes'] > 1024*1024:  # >1MB
                                        logging.warning(f"Blocking {src_ip} for DNS amplification attack")
                                        self.block_ip(src_ip, "DNS amplification attack")
                                        
            # ================ TCP SEQUENCE PREDICTION DETECTION ================
            # This detects potential TCP sequence prediction attacks by analyzing sequence patterns
            if packet.haslayer('TCP') and packet.haslayer('IP'):
                tcp = packet.getlayer('TCP')
                ip = packet.getlayer('IP')
                src_ip = ip.src
                dst_ip = ip.dst
                src_port = tcp.sport
                dst_port = tcp.dport
                seq_num = tcp.seq
                
                # Track sequence numbers for established connections
                # We're primarily interested in established connections (both sides sending data)
                if tcp.flags & 0x10:  # ACK flag is set (part of established connection)
                    connection_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    
                    with self.seq_lock:
                        # Initialize tracking for this connection if it doesn't exist yet
                        if connection_id not in self.seq_tracker:
                            self.seq_tracker[connection_id] = {
                                'seq_nums': [],
                                'first_seen': current_time,
                                'deltas': [],
                                'analyzed': False
                            }
                        
                        # Add this sequence number to our samples
                        self.seq_tracker[connection_id]['seq_nums'].append(seq_num)
                        
                        # Calculate deltas (differences between consecutive sequence numbers)
                        if len(self.seq_tracker[connection_id]['seq_nums']) >= 2:
                            idx = len(self.seq_tracker[connection_id]['seq_nums']) - 1
                            delta = self.seq_tracker[connection_id]['seq_nums'][idx] - self.seq_tracker[connection_id]['seq_nums'][idx-1]
                            # Handle sequence wraparound
                            if delta < 0:
                                delta += 2**32  # TCP sequence is 32 bit and wraps around
                            self.seq_tracker[connection_id]['deltas'].append(delta)
                        
                        # After collecting enough samples, analyze for predictability
                        if (len(self.seq_tracker[connection_id]['seq_nums']) >= self.seq_pred_sample_size and 
                                not self.seq_tracker[connection_id]['analyzed']):
                                
                            self.seq_tracker[connection_id]['analyzed'] = True
                            
                            # Check for simple patterns
                            deltas = self.seq_tracker[connection_id]['deltas']
                            
                            # Check for constant pattern (all deltas are the same)
                            constant_pattern = all(d == deltas[0] for d in deltas)
                            
                            # Check for simple linear pattern (delta between deltas is constant)
                            delta_diffs = []
                            for i in range(1, len(deltas)):
                                delta_diffs.append(deltas[i] - deltas[i-1])
                            
                            linear_pattern = False
                            if len(delta_diffs) >= 2:
                                linear_pattern = all(dd == delta_diffs[0] for dd in delta_diffs)
                            
                            # Alert if we detect potentially predictable sequence numbers
                            if constant_pattern or linear_pattern:
                                pattern_type = "constant" if constant_pattern else "linear"
                                
                                alert_key = f"seq_pred_{src_ip}"
                                if (alert_key not in self.last_alert_time or 
                                        current_time - self.last_alert_time[alert_key] > self.flood_alerting_interval):
                                    
                                    # Log the detection
                                    logging.warning(
                                        f"TCP SEQUENCE PREDICTION VULNERABILITY: {src_ip}:{src_port} has " +
                                        f"potentially predictable TCP sequence numbers ({pattern_type} pattern)")
                                    
                                    # Update last alert time
                                    self.last_alert_time[alert_key] = current_time
                                    
                                    # Increment detection statistics
                                    with self.stats_lock:
                                        if 'seq_pred_detected' not in self.stats:
                                            self.stats['seq_pred_detected'] = 0
                                        self.stats['seq_pred_detected'] += 1
                                    
                                    # We don't block here, but alert the administrator about the vulnerability
                                    print(f"{Fore.YELLOW}[WARNING] TCP SEQUENCE PREDICTION: {src_ip}:{src_port} has " +
                                          f"potentially predictable sequence numbers!{Style.RESET_ALL}")
                                    print(f"  Detected {pattern_type} pattern in sequence numbers - connection hijacking risk!")
                                    print(f"  Consider dropping this connection or implementing additional validation.")
            
            # ================ RST FLOOD DETECTION ================
            # This detects RST flood attacks which attempt to terminate legitimate connections
            if packet.haslayer('TCP') and packet.haslayer('IP'):
                tcp = packet.getlayer('TCP')
                ip = packet.getlayer('IP')
                
                # Check for RST flag
                if tcp.flags & 0x04:  # RST flag is set
                    src_ip = ip.src
                    dst_ip = ip.dst
                    dst_port = tcp.dport
                    
                    with self.rst_lock:
                        # We'll track RSTs per source IP to each destination IP:port
                        key = f"{src_ip}->{dst_ip}:{dst_port}"
                        
                        if key not in self.rst_tracker:
                            self.rst_tracker[key] = {
                                'count': 0,
                                'first_seen': current_time
                            }
                        
                        # Increment counter for this source->destination combination
                        self.rst_tracker[key]['count'] += 1
                        
                        # Check if we're seeing a flood of RST packets
                        time_window = current_time - self.rst_tracker[key]['first_seen']
                        if (time_window <= self.rst_flood_timeout and
                                self.rst_tracker[key]['count'] >= self.rst_flood_threshold):
                            
                            # Alert for RST flood (limit alert frequency)
                            alert_key = f"rst_{src_ip}"
                            if (alert_key not in self.last_alert_time or
                                    current_time - self.last_alert_time[alert_key] > self.flood_alerting_interval):
                                
                                # Log the detection
                                logging.warning(
                                    f"RST FLOOD DETECTED: {self.rst_tracker[key]['count']} RST packets from {src_ip} " +
                                    f"to {dst_ip}:{dst_port} in {time_window:.2f}s")
                                
                                # Update last alert time
                                self.last_alert_time[alert_key] = current_time
                                
                                # Increment detection statistics
                                with self.stats_lock:
                                    if 'rst_flood_detected' not in self.stats:
                                        self.stats['rst_flood_detected'] = 0
                                    self.stats['rst_flood_detected'] += 1
                                
                                # Block for severe RST floods
                                if self.rst_tracker[key]['count'] > self.rst_flood_threshold * 2:
                                    logging.warning(f"Blocking {src_ip} for RST flood attack")
                                    self.block_ip(src_ip, "RST flood attack")
            
            # ================ HTTP FLOOD DETECTION ================
            # This detects HTTP floods (Layer 7 DDoS) by analyzing traffic patterns
            # Parse HTTP if TCP is present and on common HTTP ports
            if packet.haslayer('TCP') and packet.haslayer('IP'):
                tcp = packet.getlayer('TCP')
                ip = packet.getlayer('IP')
                
                # Check for common HTTP ports (80, 443, 8080, etc.)
                is_http_port = tcp.dport in (80, 443, 8080, 8000, 8888, 8443)
                
                # Look for HTTP request signatures
                # We can't always rely on having a Raw layer for HTTP, so we use indicators like
                # common HTTP ports and certain payload patterns
                payload = None
                http_method = None
                http_path = None
                
                if packet.haslayer('Raw'):
                    payload = packet["Raw"].load
                    try:
                        # Try to decode as string - will fail if binary data
                        payload_str = payload.decode('utf-8', errors='ignore')
                        
                        # Simple check for HTTP request methods
                        http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE", "PATCH"]
                        for method in http_methods:
                            if payload_str.startswith(method + " /"):
                                http_method = method
                                # Extract the path between method and HTTP version
                                path_match = re.search(method + r" ([^\s]+) HTTP/[0-9.]+", payload_str)
                                if path_match:
                                    http_path = path_match.group(1)
                                break
                    except:
                        pass
                
                # If we identified this as an HTTP request
                if is_http_port and http_method:
                    src_ip = ip.src
                    dst_ip = ip.dst
                    dst_port = tcp.dport
                    
                    with self.http_lock:
                        # We'll track HTTP requests per source IP to each destination IP:port
                        key = f"{src_ip}->{dst_ip}:{dst_port}"
                        
                        if key not in self.http_tracker:
                            self.http_tracker[key] = {
                                'count': 0,
                                'first_seen': current_time,
                                'methods': {},  # Track HTTP methods used
                                'paths': set(),  # Track unique paths requested
                                'last_request': current_time
                            }
                        
                        # Update HTTP tracker data
                        self.http_tracker[key]['count'] += 1
                        if http_method:
                            if http_method not in self.http_tracker[key]['methods']:
                                self.http_tracker[key]['methods'][http_method] = 0
                            self.http_tracker[key]['methods'][http_method] += 1
                        if http_path:
                            self.http_tracker[key]['paths'].add(http_path)
                        self.http_tracker[key]['last_request'] = current_time
                        
                        # Check for HTTP flood conditions
                        time_window = current_time - self.http_tracker[key]['first_seen']
                        if (time_window <= self.http_flood_timeout and 
                                self.http_tracker[key]['count'] >= self.http_flood_threshold):
                            
                            # Additional suspicious indicators
                            path_count = len(self.http_tracker[key]['paths'])
                            rapid_requests = False
                            avg_requests_per_sec = self.http_tracker[key]['count'] / max(time_window, 0.001)
                            
                            # Check if this is likely an HTTP flood
                            # Various signatures: many requests in short time, automated request patterns
                            is_flood = any([
                                # High request rate alone
                                avg_requests_per_sec > self.http_flood_threshold / 2,
                                # Moderate request rate but many different paths (crawler/scanning)
                                (avg_requests_per_sec > 1 and path_count > self.http_path_threshold),
                                # Suspicious behavior: many requests to same path
                                (self.http_tracker[key]['count'] > self.http_flood_threshold * 1.5 and path_count == 1)
                            ])
                            
                            if is_flood:
                                # Alert for HTTP flood (limit alert frequency)
                                alert_key = f"http_{src_ip}"
                                if (alert_key not in self.last_alert_time or 
                                        current_time - self.last_alert_time[alert_key] > self.flood_alerting_interval):
                                    
                                    # Get method distribution
                                    method_str = ", ".join([f"{m}: {c}" for m, c in 
                                                         self.http_tracker[key]['methods'].items()])
                                    
                                    # Log the detection
                                    logging.warning(
                                        f"HTTP FLOOD DETECTED: {self.http_tracker[key]['count']} requests ({method_str}) " +
                                        f"from {src_ip} to {dst_ip}:{dst_port} across {path_count} paths in {time_window:.2f}s " +
                                        f"({avg_requests_per_sec:.1f} req/sec)")
                                    
                                    # Update last alert time
                                    self.last_alert_time[alert_key] = current_time
                                    
                                    # Increment detection statistics
                                    with self.stats_lock:
                                        if 'http_flood_detected' not in self.stats:
                                            self.stats['http_flood_detected'] = 0
                                        self.stats['http_flood_detected'] += 1
                                    
                                    # Block for severe HTTP floods
                                    if avg_requests_per_sec > self.http_flood_threshold:
                                        logging.warning(f"Blocking {src_ip} for HTTP flood attack")
                                        self.block_ip(src_ip, "HTTP flood attack")
                                        
            # ================ SLOW ATTACK DETECTION ================
            # This detects slow application layer attacks like Slowloris
            # These attacks keep connections open for long periods with minimal data transfer
            if packet.haslayer('TCP') and packet.haslayer('IP'):
                tcp = packet.getlayer('TCP')
                ip = packet.getlayer('IP')
                
                # We're interested in established connections (both ACK and SYN flags)
                if tcp.flags & 0x12 == 0x12:  # Both SYN and ACK flags set (connection establishing)
                    src_ip = ip.src
                    dst_ip = ip.dst
                    dst_port = tcp.dport
                    src_port = tcp.sport
                    
                    # Create connection identifier for both directions
                    conn_id = f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}"
                    
                    with self.slow_lock:
                        # Track connection start time
                        if conn_id not in self.slow_tracker:
                            self.slow_tracker[conn_id] = {
                                'start_time': current_time,
                                'last_activity': current_time,
                                'bytes_transferred': 0,
                                'packets': 0,
                                'source_ip': src_ip
                            }
                        
                        # Update connection tracker
                        self.slow_tracker[conn_id]['last_activity'] = current_time
                        self.slow_tracker[conn_id]['packets'] += 1
                        
                        # Add size of payload if present
                        if packet.haslayer('Raw'):
                            self.slow_tracker[conn_id]['bytes_transferred'] += len(packet['Raw'].load)
                        else:
                            # Count at least TCP header size
                            self.slow_tracker[conn_id]['bytes_transferred'] += len(packet[TCP])
                            
                # Look for packets in connections that stay open but transfer minimal data
                # This is key for detecting slow attacks - lots of tiny packets keeping connections open
                if tcp.flags & 0x10:  # ACK flag set (established connection)
                    src_ip = ip.src
                    dst_ip = ip.dst
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    
                    # Check both connection directions
                    conn_id1 = f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}"
                    conn_id2 = f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}"
                    
                    conn_id = None
                    if conn_id1 in self.slow_tracker:
                        conn_id = conn_id1
                    elif conn_id2 in self.slow_tracker:
                        conn_id = conn_id2
                    
                    if conn_id:
                        with self.slow_lock:
                            # Update connection tracker
                            self.slow_tracker[conn_id]['last_activity'] = current_time
                            self.slow_tracker[conn_id]['packets'] += 1
                            
                            # Add size of payload if present
                            if packet.haslayer('Raw'):
                                self.slow_tracker[conn_id]['bytes_transferred'] += len(packet['Raw'].load)
                            else:
                                # Count at least TCP header size
                                self.slow_tracker[conn_id]['bytes_transferred'] += len(packet[TCP])
                            
                            # Check for slow attack indicators
                            connection_age = current_time - self.slow_tracker[conn_id]['start_time']
                            bytes_per_second = self.slow_tracker[conn_id]['bytes_transferred'] / max(connection_age, 0.001)
                            source_ip = self.slow_tracker[conn_id]['source_ip']
                            
                            # Count slow connections per source IP
                            slow_connections_from_ip = 0
                            for cid, data in self.slow_tracker.items():
                                if (data['source_ip'] == source_ip and
                                        current_time - data['start_time'] >= self.slow_conn_duration and
                                        data['bytes_transferred'] / max(current_time - data['start_time'], 0.001) < 50):
                                    slow_connections_from_ip += 1
                            
                            # Detect slow connection patterns
                            if (connection_age >= self.slow_conn_duration and
                                    bytes_per_second < 50 and  # Very low data rate
                                    slow_connections_from_ip >= self.slow_conn_threshold):
                                
                                # Alert for slow attack (limit alert frequency)
                                alert_key = f"slow_{source_ip}"
                                if (alert_key not in self.last_alert_time or
                                        current_time - self.last_alert_time[alert_key] > self.flood_alerting_interval):
                                    
                                    # Log the detection
                                    logging.warning(
                                        f"SLOW ATTACK DETECTED: {source_ip} has {slow_connections_from_ip} slow connections " +
                                        f"(avg {bytes_per_second:.1f} B/s) open for {connection_age:.1f}s")
                                    
                                    # Update last alert time
                                    self.last_alert_time[alert_key] = current_time
                                    
                                    # Increment detection statistics
                                    with self.stats_lock:
                                        if 'slow_attack_detected' not in self.stats:
                                            self.stats['slow_attack_detected'] = 0
                                        self.stats['slow_attack_detected'] += 1
                                    
                                    # Block for severe slow attacks
                                    if slow_connections_from_ip > self.slow_conn_threshold * 2:
                                        logging.warning(f"Blocking {source_ip} for slow attack (possible Slowloris)")
                                        self.block_ip(source_ip, "Slow attack (possible Slowloris)")
                                        
            # ================ HONEYPOT DETECTION ================
            # This detects attackers probing for vulnerable services using decoy ports
            if self.honeypot_enabled and packet.haslayer('TCP') and packet.haslayer('IP'):
                tcp = packet.getlayer('TCP')
                ip = packet.getlayer('IP')
                
                # Check if the packet is targeting one of our honeypot ports
                if tcp.dport in self.honeypot_ports:
                    src_ip = ip.src
                    dst_port = tcp.dport
                    
                    # Skip if the source is in our whitelist
                    if src_ip in self.whitelist:
                        return
                        
                    with self.honeypot_lock:
                        # Initialize tracker for this source if not exists
                        if src_ip not in self.honeypot_tracker:
                            self.honeypot_tracker[src_ip] = {
                                'first_seen': current_time,
                                'attempts': {},
                                'total_attempts': 0
                            }
                        
                        # Update port attempt counter
                        if dst_port not in self.honeypot_tracker[src_ip]['attempts']:
                            self.honeypot_tracker[src_ip]['attempts'][dst_port] = 0
                            
                        self.honeypot_tracker[src_ip]['attempts'][dst_port] += 1
                        self.honeypot_tracker[src_ip]['total_attempts'] += 1
                        
                        # Check detection conditions
                        time_window = current_time - self.honeypot_tracker[src_ip]['first_seen']
                        unique_ports = len(self.honeypot_tracker[src_ip]['attempts'])
                        total_attempts = self.honeypot_tracker[src_ip]['total_attempts']
                        
                        # Alert conditions: multiple honeypot ports probed or repeated attempts
                        is_malicious = False
                        reason = ""
                        
                        if time_window <= self.honeypot_detection_window:
                            # Multiple honeypot ports probed
                            if unique_ports >= self.honeypot_threshold:
                                is_malicious = True
                                reason = f"probed {unique_ports} honeypot ports"
                            # Repeated attempts on same port
                            elif any(attempts >= self.honeypot_threshold for port, attempts in 
                                    self.honeypot_tracker[src_ip]['attempts'].items()):
                                is_malicious = True
                                reason = "repeated attempts on honeypot port"
                                
                        if is_malicious:
                            # Alert for honeypot detection (limit alert frequency)
                            alert_key = f"honeypot_{src_ip}"
                            if (alert_key not in self.last_alert_time or
                                    current_time - self.last_alert_time[alert_key] > self.flood_alerting_interval):
                                
                                # Format the ports and attempt counts for logging
                                port_attempts = [
                                    f"{port}: {count}" 
                                    for port, count in self.honeypot_tracker[src_ip]['attempts'].items()
                                ]
                                
                                # Log the detection
                                logging.warning(
                                    f"HONEYPOT DETECTION: {src_ip} {reason} in {time_window:.1f}s " +
                                    f"(ports: {', '.join(port_attempts)})")
                                
                                # Update last alert time
                                self.last_alert_time[alert_key] = current_time
                                
                                # Increment detection statistics
                                with self.stats_lock:
                                    if 'honeypot_detected' not in self.stats:
                                        self.stats['honeypot_detected'] = 0
                                    self.stats['honeypot_detected'] += 1
                                
                                # Block for serious honeypot probes
                                    if total_attempts > self.honeypot_threshold * 2 or unique_ports > self.honeypot_threshold:
                                        logging.warning(f"Blocking {src_ip} for honeypot probe activity")
                                        self.block_ip(src_ip, "Honeypot probe detection")
                                        
            # ================ DNS TUNNELING DETECTION ================
            # This detects DNS tunneling attempts which are often used for data exfiltration
            # or as covert command and control channels
            if self.dns_tunnel_enabled and packet.haslayer('DNS') and packet.haslayer('IP'):
                dns = packet.getlayer('DNS')
                ip = packet.getlayer('IP')
                
                # We're primarily interested in DNS queries (not responses)
                if dns.qr == 0:  # DNS query
                    src_ip = ip.src
                    
                    # Skip if the source is in our whitelist
                    if src_ip in self.whitelist:
                        return
                    
                    # Extract the query name
                    if dns.qd and dns.qd.qname:
                        try:
                            # Convert DNS qname from bytes to string and remove trailing dot
                            query = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                            
                            # Skip common legitimate queries and local queries
                            skip_domains = ['local', 'arpa', 'localdomain', 'localhost', 'home', 'lan']
                            if any(query.endswith(d) for d in skip_domains):
                                return
                            
                            # Calculate suspicious indicators
                            with self.dns_tunnel_lock:
                                # Initialize tracking for this source IP
                                if src_ip not in self.dns_tunnel_tracker:
                                    self.dns_tunnel_tracker[src_ip] = {
                                        'first_seen': current_time,
                                        'queries': [],
                                        'total_queries': 0,
                                        'last_alert': 0
                                    }
                                
                                # Store query with timestamp
                                self.dns_tunnel_tracker[src_ip]['queries'].append((current_time, query))
                                self.dns_tunnel_tracker[src_ip]['total_queries'] += 1
                                
                                # Prune old queries outside our detection window
                                self.dns_tunnel_tracker[src_ip]['queries'] = [
                                    (ts, q) for ts, q in self.dns_tunnel_tracker[src_ip]['queries']
                                    if current_time - ts <= self.dns_tunnel_timeout
                                ]
                                
                                # Extract current queries in our time window
                                queries_in_window = self.dns_tunnel_tracker[src_ip]['queries']
                                
                                # Calculate suspicious metrics only if we have enough queries
                                if len(queries_in_window) >= 5:
                                    # Check subdomain depth
                                    subdomain_counts = []
                                    # Check query length
                                    long_queries = []
                                    # Check entropy (randomness) of hostnames
                                    high_entropy_queries = []
                                    
                                    for _, q in queries_in_window:
                                        # Count subdomains
                                        parts = q.split('.')
                                        subdomain_count = len(parts) - 2  # -2 for TLD and domain
                                        subdomain_counts.append(subdomain_count)
                                        
                                        # Check for unusually long hostnames
                                        if any(len(part) > self.dns_length_threshold for part in parts):
                                            long_queries.append(q)
                                        
                                        # Calculate entropy for the first subdomain part
                                        # High entropy suggests randomized/encoded data
                                        if len(parts) > 0 and len(parts[0]) > 8:  # Skip short names
                                            hostname = parts[0]
                                            entropy = self.calculate_entropy(hostname)
                                            if entropy > self.dns_entropy_threshold:
                                                high_entropy_queries.append((q, entropy))
                                    
                                    # Detection logic - consider multiple indicators
                                    is_suspicious = False
                                    reason = ""
                                    
                                    # Suspicious if consistently deep subdomains
                                    if len([c for c in subdomain_counts if c >= self.dns_subdomain_threshold]) >= 3:
                                        is_suspicious = True
                                        reason = "excessive subdomain depth"
                                    
                                    # Suspicious if consistently long hostnames (encoded data)
                                    elif len(long_queries) >= 3:
                                        is_suspicious = True
                                        reason = "unusually long query names"
                                    
                                    # Suspicious if high entropy hostnames (suggesting encoded data)
                                    elif len(high_entropy_queries) >= 3:
                                        is_suspicious = True
                                        reason = "high entropy (randomness) in queries"
                                    
                                    # Suspicious if very high query rate
                                    query_rate = len(queries_in_window) / self.dns_tunnel_timeout
                                    if query_rate > 1.0:  # More than 1 per second average
                                        is_suspicious = True
                                        reason = f"high query rate ({query_rate:.1f}/sec)"
                                    
                                    # Alert if suspicious (limit alert frequency)
                                    if is_suspicious:
                                        # Don't alert more than once per minute for the same source
                                        if current_time - self.dns_tunnel_tracker[src_ip]['last_alert'] > 60:
                                            # Format recent queries for logging
                                            recent_queries = [q for _, q in queries_in_window[-5:]]
                                            
                                            # Log the detection
                                            logging.warning(
                                                f"DNS TUNNELING SUSPECTED from {src_ip}: {reason}, " +
                                                f"{len(queries_in_window)} queries in {self.dns_tunnel_timeout}s. " +
                                                f"Recent examples: {', '.join(recent_queries)}")
                                            
                                            # If additional indicators of tunneling are present, block
                                            severity = 0
                                            if len([c for c in subdomain_counts if c >= self.dns_subdomain_threshold]) >= 5:
                                                severity += 1
                                            if len(long_queries) >= 5:
                                                severity += 1
                                            if len(high_entropy_queries) >= 5:
                                                severity += 1
                                            if query_rate > 2.0:  # Very high rate
                                                severity += 1
                                                
                                            # Update last alert time
                                            self.dns_tunnel_tracker[src_ip]['last_alert'] = current_time
                                            
                                            # Increment detection statistics
                                            with self.stats_lock:
                                                if 'dns_tunnel_detected' not in self.stats:
                                                    self.stats['dns_tunnel_detected'] = 0
                                                self.stats['dns_tunnel_detected'] += 1
                                            
                                            # Block for definite DNS tunneling activity
                                            if severity >= 2:
                                                logging.warning(f"Blocking {src_ip} for DNS tunneling activity")
                                                self.block_ip(src_ip, "DNS tunneling")
                        except Exception as e:
                            logging.debug(f"Error analyzing DNS query: {str(e)}")
                            pass
                            
            # ================ VPN/PROXY DETECTION ================
            # This detects connections from known VPN/proxy providers which may be used to hide attacks
            if self.vpn_proxy_enabled and packet.haslayer('IP'):
                ip = packet.getlayer('IP')
                src_ip = ip.src
                
                # Skip if the source is in our whitelist
                if src_ip in self.whitelist:
                    return
                    
                # Skip local/private IPs
                if self.is_private_ip(src_ip):
                    return
                    
                try:
                    with self.vpn_proxy_lock:
                        current_time = time.time()
                        
                        # Initialize tracking for this IP if not exists
                        if src_ip not in self.vpn_proxy_tracker:
                            self.vpn_proxy_tracker[src_ip] = {
                                'first_seen': current_time,
                                'last_seen': current_time,
                                'connection_count': 0,
                                'is_vpn': False,
                                'is_proxy': False,
                                'check_time': 0,
                                'country': None,
                                'last_alert': 0
                            }
                        
                        # Update tracking
                        tracker = self.vpn_proxy_tracker[src_ip]
                        tracker['last_seen'] = current_time
                        tracker['connection_count'] += 1
                        
                        # Only check if we haven't checked recently (to avoid API rate limits)
                        if current_time - tracker['check_time'] > self.vpn_proxy_check_interval:
                            # First check cache
                            if src_ip in self.vpn_proxy_cache:
                                cache_time, is_vpn, is_proxy, country = self.vpn_proxy_cache[src_ip]
                                
                                # Use cached result if still valid
                                if current_time - cache_time < self.vpn_proxy_cache_timeout:
                                    tracker['is_vpn'] = is_vpn
                                    tracker['is_proxy'] = is_proxy
                                    tracker['country'] = country
                                    tracker['check_time'] = current_time
                                else:
                                    # Cache expired, remove it
                                    del self.vpn_proxy_cache[src_ip]
                            
                            # If not in cache or expired, check with ipapi
                            if src_ip not in self.vpn_proxy_cache:
                                try:
                                    # Query ipapi for this IP
                                    data = ipapi.location(ip=src_ip, output='json')
                                    
                                    if data and isinstance(data, dict):
                                        # Extract VPN/proxy information
                                        is_vpn = data.get('security', {}).get('is_vpn', False)
                                        is_proxy = data.get('security', {}).get('is_proxy', False)
                                        country = data.get('country_name')
                                        
                                        # Update tracker
                                        tracker['is_vpn'] = is_vpn
                                        tracker['is_proxy'] = is_proxy
                                        tracker['country'] = country
                                        tracker['check_time'] = current_time
                                        
                                        # Cache the result
                                        self.vpn_proxy_cache[src_ip] = (current_time, is_vpn, is_proxy, country)
                                except Exception as e:
                                    logging.debug(f"Error querying ipapi for {src_ip}: {str(e)}")
                        
                        # Detection logic
                        if (tracker['is_vpn'] or tracker['is_proxy']) and tracker['connection_count'] >= self.vpn_proxy_threshold:
                            # Don't alert more than once every 5 minutes for the same IP
                            if current_time - tracker['last_alert'] > 300:
                                vpn_type = "VPN" if tracker['is_vpn'] else "proxy"
                                country_info = f" from {tracker['country']}" if tracker['country'] else ""
                                
                                logging.warning(
                                    f"Suspicious {vpn_type} connection detected from {src_ip}{country_info} - "
                                    f"{tracker['connection_count']} connections"
                                )
                                
                                # Increment stats
                                with self.stats_lock:
                                    if 'vpn_proxy_detected' not in self.stats:
                                        self.stats['vpn_proxy_detected'] = 0
                                    self.stats['vpn_proxy_detected'] += 1
                                
                                # Update last alert time
                                tracker['last_alert'] = current_time
                                
                                # Block if high volume of connections
                                if tracker['connection_count'] >= self.vpn_proxy_threshold * 3:
                                    logging.warning(f"Blocking {src_ip} for high volume {vpn_type} traffic")
                                    self.block_ip(src_ip, f"High volume {vpn_type} traffic")
                except Exception as e:
                    logging.error(f"Error in VPN/proxy detection: {str(e)}")
                    pass
                    
            # ================ WEBSOCKET & HTTP/2 ATTACK DETECTION ================
            # This detects WebSocket & HTTP/2 flooding attacks which are increasingly common
            # as they bypass traditional rate limiters and WAFs
            if (self.websocket_enabled or self.http2_enabled) and packet.haslayer('TCP') and packet.haslayer('IP'):
                ip = packet.getlayer('IP')
                tcp = packet.getlayer('TCP')
                src_ip = ip.src
                dst_port = tcp.dport
                payload = None
                
                # Skip if the source is in our whitelist
                if src_ip in self.whitelist:
                    return
                    
                # Check for WebSocket and HTTP/2 traffic (usually on 80, 443, 8080, etc.)
                if self.websocket_enabled and tcp.payload and dst_port in [80, 443, 8080, 8443]:
                    try:
                        # Try to extract and inspect the payload
                        if hasattr(tcp, 'load'):
                            payload = tcp.load
                        elif hasattr(tcp, 'payload') and hasattr(tcp.payload, 'load'):
                            payload = tcp.payload.load
                            
                        if payload and isinstance(payload, bytes):
                            payload_str = payload.decode('utf-8', errors='ignore')
                            
                            # Look for WebSocket signatures
                            is_websocket = False
                            if 'Upgrade: websocket' in payload_str or 'Sec-WebSocket-Key:' in payload_str:
                                is_websocket = True  # WebSocket handshake
                            elif payload_str and len(payload) > 2:  # Check actual WebSocket frames
                                # Simple heuristic: WebSocket frames often start with bytes in range 0x80-0x8F
                                frame_byte = payload[0] if isinstance(payload[0], int) else ord(payload[0])
                                if 0x80 <= frame_byte <= 0x8F:
                                    is_websocket = True
                                    
                            if is_websocket:
                                current_time = time.time()
                                with self.websocket_lock:  # Reusing same lock for related protocols
                                    # Initialize tracking for this IP if not exists
                                    if src_ip not in self.websocket_tracker:
                                        self.websocket_tracker[src_ip] = {
                                            'first_seen': current_time,
                                            'last_seen': current_time,
                                            'websocket_count': 0,
                                            'http2_count': 0,
                                            'last_alert': 0,
                                            'websocket_rate': [],  # Track WebSocket frame arrival times
                                            'http2_rate': [],  # Track HTTP/2 frame arrival times
                                            'websocket_endpoints': set(),  # Track WebSocket endpoints being targeted
                                            'http2_endpoints': set()  # Track HTTP/2 endpoints being targeted
                                        }
                                    
                                    # Update tracking
                                    tracker = self.websocket_tracker[src_ip]
                                    tracker['last_seen'] = current_time
                                    tracker['websocket_count'] += 1
                                    
                                    # Track WebSocket rate with sliding window
                                    tracker['websocket_rate'].append(current_time)
                                    if len(tracker['websocket_rate']) > 10:
                                        tracker['websocket_rate'] = tracker['websocket_rate'][-10:]
                                    
                                    # Extract WebSocket target info if possible (simplified)
                                    ws_path = "unknown"
                                    if b'Sec-WebSocket-Protocol:' in payload:
                                        try:
                                            path_start = payload.find(b'Sec-WebSocket-Protocol:') + 23
                                            path_end = payload.find(b'\r\n', path_start)
                                            if path_end > path_start:
                                                ws_path = payload[path_start:path_end].decode('utf-8', errors='ignore').strip()
                                                tracker['websocket_endpoints'].add(ws_path)
                                        except Exception:
                                            pass
                                    
                                    # Also try to extract the target URI 
                                    if b'GET ' in payload and b' HTTP/' in payload:
                                        try:
                                            uri_start = payload.find(b'GET ') + 4
                                            uri_end = payload.find(b' HTTP/', uri_start)
                                            if uri_end > uri_start:
                                                uri = payload[uri_start:uri_end].decode('utf-8', errors='ignore').strip()
                                                tracker['websocket_endpoints'].add(uri)
                                        except Exception:
                                            pass
                                            
                                    # Check for WebSocket flooding attacks
                                    detection_window = 5  # 5 seconds
                                    rate_threshold = 50   # 50 frames within detection window is suspicious
                                    current_rate = sum(1 for t in tracker['websocket_rate'] if current_time - t <= detection_window)
                                    
                                    if (current_rate >= rate_threshold and 
                                            tracker['websocket_count'] > 100 and 
                                            current_time - tracker.get('last_alert', 0) > 60):  # Alert at most once per minute
                                        
                                        # Potential WebSocket flood attack detected
                                        alert_msg = f"Potential WebSocket flood attack from {src_ip}: {current_rate} frames in {detection_window}s"
                                        self.alert(alert_msg, src_ip, 'websocket_flood', severity=3)
                                        tracker['last_alert'] = current_time
                                        
                                        if self.protection_level >= 2:
                                            self.block_ip(src_ip, "WebSocket flood attack", block_time=600)
                            
                            # Check for HTTP/2 traffic signatures
                            is_http2 = False
                            if payload and isinstance(payload, bytes):
                                # HTTP/2 preface magic starts with 'PRI * HTTP/2.0'
                                if b'PRI * HTTP/2.0' in payload:
                                    is_http2 = True
                                # HTTP/2 frames often begin with a specific pattern
                                elif len(payload) > 9 and payload[0] in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]:
                                    # Simple heuristic: HTTP/2 frame header check
                                    if payload[3] in [0, 1, 2, 4, 6, 8]:  # Common HTTP/2 frame types
                                        is_http2 = True
                                
                            if is_http2:
                                current_time = time.time()
                                with self.websocket_lock:  # Reusing same lock for related protocols
                                    # Initialize tracking for this IP if not exists
                                    if src_ip not in self.websocket_tracker:
                                        self.websocket_tracker[src_ip] = {
                                            'first_seen': current_time,
                                            'last_seen': current_time,
                                            'websocket_count': 0,
                                            'http2_count': 0,
                                            'last_alert': 0,
                                            'websocket_rate': [],  # Track WebSocket frame arrival times
                                            'http2_rate': [],  # Track HTTP/2 frame arrival times
                                            'websocket_endpoints': set(),  # Track WebSocket endpoints being targeted
                                            'http2_endpoints': set()  # Track HTTP/2 endpoints being targeted
                                        }
                                    
                                    # Update tracking
                                    tracker = self.websocket_tracker[src_ip]
                                    tracker['last_seen'] = current_time
                                    tracker['websocket_count'] += 1
                                    
                                    # Track WebSocket rate with sliding window
                                    tracker['websocket_rate'].append(current_time)
                                    if len(tracker['websocket_rate']) > 10:
                                        tracker['websocket_rate'] = tracker['websocket_rate'][-10:]
                                    
                                    # Extract WebSocket target info if possible (simplified)
                                    ws_path = "unknown"
                                    if b'Sec-WebSocket-Protocol:' in payload:
                                        try:
                                            path_start = payload.find(b'Sec-WebSocket-Protocol:') + 23
                                            path_end = payload.find(b'\r\n', path_start)
                                            if path_end > path_start:
                                                ws_path = payload[path_start:path_end].decode('utf-8', errors='ignore').strip()
                                                tracker['websocket_endpoints'].add(ws_path)
                                        except Exception:
                                            pass
                                    
                                    # Also try to extract the target URI 
                                    if b'GET ' in payload and b' HTTP/' in payload:
                                        try:
                                            uri_start = payload.find(b'GET ') + 4
                                            uri_end = payload.find(b' HTTP/', uri_start)
                                            if uri_end > uri_start:
                                                uri = payload[uri_start:uri_end].decode('utf-8', errors='ignore').strip()
                                                tracker['websocket_endpoints'].add(uri)
                                        except Exception:
                                            pass
                                            
                                    # Check for WebSocket flooding attacks
                                    detection_window = 5  # 5 seconds
                                    rate_threshold = 50   # 50 frames within detection window is suspicious
                                    current_rate = sum(1 for t in tracker['websocket_rate'] if current_time - t <= detection_window)
                                    
                                    if (current_rate >= rate_threshold and 
                                            tracker['websocket_count'] > 100 and 
                                            current_time - tracker.get('last_alert', 0) > 60):  # Alert at most once per minute
                                        
                                        # Potential WebSocket flood attack detected
                                        alert_msg = f"Potential WebSocket flood attack from {src_ip}: {current_rate} frames in {detection_window}s"
                                        self.alert(alert_msg, src_ip, 'websocket_flood', severity=3)
                                        tracker['last_alert'] = current_time
                                        
                                        if self.protection_level >= 2:
                                            self.block_ip(src_ip, "WebSocket flood attack", block_time=600)
                            
                            # Check for HTTP/2 traffic signatures
                            is_http2 = False
                            if payload and isinstance(payload, bytes):
                                # HTTP/2 preface magic starts with 'PRI * HTTP/2.0'
                                if b'PRI * HTTP/2.0' in payload:
                                    is_http2 = True
                                # HTTP/2 frames often begin with a specific pattern
                                elif len(payload) > 9 and payload[0] in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]:
                                    # Simple heuristic: HTTP/2 frame header check
                                    if payload[3] in [0, 1, 2, 4, 6, 8]:  # Common HTTP/2 frame types
                                        is_http2 = True
                                
                            if is_http2:
                                current_time = time.time()
                                with self.websocket_lock:  # Reusing same lock for related protocols
                                    # Initialize tracking for this IP if not exists
                                    if src_ip not in self.websocket_tracker:
                                        self.websocket_tracker[src_ip] = {
                                            'first_seen': current_time,
                                            'last_seen': current_time,
                                            'websocket_count': 0,
                                            'http2_count': 0,
                                            'last_alert': 0,
                                            'websocket_rate': [],  # Track WebSocket frame arrival times
                                            'http2_rate': [],  # Track HTTP/2 frame arrival times
                                            'websocket_endpoints': set(),  # Track WebSocket endpoints being targeted
                                            'http2_endpoints': set()  # Track HTTP/2 endpoints being targeted
                                        }
                                    
                                    # Update tracking
                                    tracker = self.websocket_tracker[src_ip]
                                    tracker['last_seen'] = current_time
                                    tracker['http2_count'] += 1
                                    
                                    # Track HTTP/2 rate with sliding window
                                    tracker['http2_rate'].append(current_time)
                                    if len(tracker['http2_rate']) > 10:
                                        tracker['http2_rate'] = tracker['http2_rate'][-10:]
                                        
                                    # Extract target URI if possible (simplified)
                                    uri_path = "unknown"
                                    if b':path:' in payload:
                                        try:
                                            path_start = payload.find(b':path:') + 6
                                            path_end = payload.find(b'\r\n', path_start)
                                            if path_end > path_start:
                                                uri_path = payload[path_start:path_end].decode('utf-8', errors='ignore').strip()
                                                tracker['http2_endpoints'].add(uri_path)
                                        except Exception:
                                            pass
                                            
                                    # Check for HTTP/2 flooding attacks
                                    detection_window = 5  # 5 seconds
                                    rate_threshold = 60   # 60 frames within detection window is suspicious
                                    current_rate = sum(1 for t in tracker['http2_rate'] if current_time - t <= detection_window)
                                    
                                    if (current_rate >= rate_threshold and 
                                            tracker['http2_count'] > 120 and 
                                            current_time - tracker.get('last_alert', 0) > 60):  # Alert at most once per minute
                                        
                                        # Potential HTTP/2 flood attack detected
                                        alert_msg = f"Potential HTTP/2 flood attack from {src_ip}: {current_rate} frames in {detection_window}s"
                                        self.alert(alert_msg, src_ip, 'http2_flood', severity=3)
                                        tracker['last_alert'] = current_time
                                        
                                        if self.protection_level >= 2:
                                            self.block_ip(src_ip, "HTTP/2 flood attack", block_time=600)
                                            # Stats tracking for HTTP/2 flood attacks
                                            with self.stats_lock:
                                                if 'http2_flood_detected' not in self.stats:
                                                    self.stats['http2_flood_detected'] = 0
                                                self.stats['http2_flood_detected'] += 1
                    except Exception as e:
                        logging.debug(f"Error analyzing WebSocket or HTTP/2 packet: {str(e)}")
                
                # SYN flood detection for any connection
                if dst_port not in [53, 123]:  # Skip DNS and NTP
                    try:
                        # SYN flood detection logic starts here
                        current_time = time.time()
                        
                        # Check if this is a SYN packet
                        if flags & 0x02 and not flags & 0x10:  # SYN flag set, ACK flag not set
                            with self.syn_lock:
                                # Initialize tracking for this IP if not exists
                                if src_ip not in self.syn_tracker:
                                    self.syn_tracker[src_ip] = {
                                        'first_seen': current_time,
                                        'count': 0,
                                        'last_seen': current_time,
                                        'ports': set(),
                                        'last_alert': 0, 
                                        'syn_rate': [],  # Track packet arrival times for rate calculation
                                        'repeat_ports': {},  # Track repeated SYNs to same port
                                    }
                                
                                # Update tracking
                                tracker = self.syn_tracker[src_ip]
                                tracker['count'] += 1
                                tracker['last_seen'] = current_time
                                tracker['ports'].add(dst_port)
                                
                                # Track SYN rate with sliding window
                                tracker['syn_rate'].append(current_time)
                                if len(tracker['syn_rate']) > 20:  # Limit this to avoid excessive memory usage
                                    tracker['syn_rate'] = tracker['syn_rate'][-20:]
                                
                                # Track repeated SYNs to the same port
                                if dst_port in tracker['repeat_ports']:
                                    tracker['repeat_ports'][dst_port] += 1
                                else:
                                    tracker['repeat_ports'][dst_port] = 1
                    except Exception as e:
                        logging.debug(f"Error in SYN flood detection: {str(e)}")
                        
            # SYN flood detection will be implemented here
            # For now we'll continue with other packet processing
            
            # Begin basic threat analysis for all packet types
            if not packet.haslayer('IP'):
                return
                
            # Get the IP layer for analysis
            ip = packet.getlayer('IP')
            src_ip = ip.src
            dst_ip = ip.dst
            
            # For TCP packets, analyze for threats
            if packet.haslayer('TCP'):
                tcp = packet.getlayer('TCP')
                src_port = tcp.sport
                dst_port = tcp.dport
                
                # Check for SYN flood
                if tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN but not ACK
                    self._check_syn_flood(src_ip, dst_ip, dst_port, current_time)
                # Check for port scan attempts
                self._check_port_scan(src_ip, dst_ip, dst_port, current_time)
                
                # Check for TCP flag manipulation (NULL, XMAS, FIN scans)
                self._check_tcp_flags(tcp.flags, src_ip, dst_ip, current_time)
                
                # Track sequence number anomalies
                self._check_sequence_anomaly(src_ip, tcp.seq, current_time)
            
            # UDP attack detection
            elif packet.haslayer('UDP'):
                udp = packet.getlayer('UDP')
                self._check_udp_flood(src_ip, dst_ip, udp.dport, current_time)
            
            # ICMP attack detection  
            elif packet.haslayer('ICMP'):
                icmp = packet.getlayer('ICMP')
                self._check_icmp_flood(src_ip, dst_ip, current_time)
            
            # Check for fragmentation attacks
            self._check_fragmentation(ip, src_ip, current_time)
            
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")
                
    def _check_syn_flood(self, src_ip, dst_ip, dst_port, current_time):
        """Check for SYN flood attacks with enhanced detection and detailed logging"""
        with self.syn_lock:
            # Create tracker for source IP if it doesn't exist
            if src_ip not in self.syn_tracker:
                self.syn_tracker[src_ip] = {
                    'count': 0,
                    'ports': set(),
                    'first_seen': current_time,
                    'syn_rate': [],
                    'repeat_ports': {},
                    'attack_pattern': '', 
                    'severity_level': 0,
                    'peak_rate': 0,
                    'detection_details': {}
                }
            
            # Update tracking
            tracker = self.syn_tracker[src_ip]
            tracker['count'] += 1
            tracker['ports'].add(dst_port)
            
            # Track SYN rate with multiple time windows for better pattern detection
            tracker['syn_rate'].append(current_time)
            if len(tracker['syn_rate']) > 100:  # Extended tracking for better pattern recognition
                tracker['syn_rate'] = tracker['syn_rate'][-100:]
            
            # Track repeated SYNs to the same port - important for targeted attacks
            if dst_port in tracker['repeat_ports']:
                tracker['repeat_ports'][dst_port] += 1
            else:
                tracker['repeat_ports'][dst_port] = 1
            
            # Multi-dimensional SYN flood detection using various time windows
            time_windows = {'ultrafast': 1, 'fast': 3, 'medium': 5, 'extended': 10}
            detection_results = {}
            
            # Calculate SYN rates for different time windows
            for window_name, window_size in time_windows.items():
                count = sum(1 for t in tracker['syn_rate'] if current_time - t <= window_size)
                rate = count / window_size if window_size > 0 else 0
                detection_results[window_name] = {
                    'count': count,
                    'rate': rate, 
                    'window': window_size
                }
                
            # Update peak rate if current rate is higher
            current_peak_rate = max(result['rate'] for result in detection_results.values())
            if current_peak_rate > tracker.get('peak_rate', 0):
                tracker['peak_rate'] = current_peak_rate
            
            # Determine attack pattern and severity
            severity = 0
            attack_pattern = ''
            
            # Pattern 1: Rapid burst - extremely high rate in very short window
            if detection_results['ultrafast']['count'] >= 30:
                severity = max(severity, 4)
                attack_pattern = 'Rapid Burst Attack'
            
            # Pattern 2: Sustained high rate
            elif detection_results['medium']['count'] >= 50 and detection_results['extended']['count'] >= 80:
                severity = max(severity, 3)
                attack_pattern = 'Sustained High-Rate Attack'
            
            # Pattern 3: Distributed lower rate
            elif detection_results['extended']['count'] >= 50 and len(tracker['ports']) > 10:
                severity = max(severity, 2)
                attack_pattern = 'Distributed Port Attack'
            
            # Pattern 4: Targeted attack - many SYNs to same port
            max_port_hits = max(tracker['repeat_ports'].values()) if tracker['repeat_ports'] else 0
            if max_port_hits >= 30:
                severity = max(severity, 3)
                most_hit_port = max(tracker['repeat_ports'].items(), key=lambda x: x[1])[0]
                attack_pattern = f'Targeted Port Attack (Port {most_hit_port})'
            
            # Store detection details
            tracker['detection_details'] = detection_results
            tracker['severity_level'] = severity
            if attack_pattern:
                tracker['attack_pattern'] = attack_pattern
            
            # Alert if attack is detected and we haven't alerted recently
            if (severity >= 2 and 
                    current_time - tracker.get('last_alert', 0) > 30):  # Rate limit alerts to every 30s
                
                # Prepare detailed alert message
                most_targeted_ports = sorted(tracker['repeat_ports'].items(), key=lambda x: x[1], reverse=True)[:3]
                port_details = ", ".join([f"port {port}: {count} SYNs" for port, count in most_targeted_ports])
                
                alert_msg = f"SYN FLOOD ATTACK DETECTED - {attack_pattern}\n" \
                          f"Source: {src_ip} | Severity: {severity}/4\n" \
                          f"Total SYNs: {tracker['count']} | Peak Rate: {tracker['peak_rate']:.2f} pkts/sec\n" \
                          f"Distinct Ports: {len(tracker['ports'])} | Most targeted: {port_details}\n" \
                          f"1s rate: {detection_results['ultrafast']['rate']:.2f} | 5s rate: {detection_results['medium']['rate']:.2f} pkts/sec"
                
                # Log with appropriate severity
                self.alert(alert_msg, src_ip, 'syn_flood', severity=severity)
                logging.warning(f"SYN FLOOD: {src_ip} - {attack_pattern} - Severity {severity}/4")
                
                # Print to console with color based on severity
                colors = {2: Fore.YELLOW, 3: Fore.RED, 4: Fore.MAGENTA}
                print(f"\n{colors.get(severity, Fore.RED)}[SYN FLOOD ATTACK - {attack_pattern}] {src_ip}{Style.RESET_ALL}")
                
                # Take protective action based on severity
                if severity >= 3 and self.protection_level >= 2:
                    self.block_ip(src_ip, f"SYN flood attack - {attack_pattern}")
                    print(f"{Fore.GREEN}[PROTECTION] Blocked {src_ip} due to SYN flood attack{Style.RESET_ALL}")
                elif severity == 2 and self.protection_level >= 3:
                    self.block_ip(src_ip, f"SYN flood attack - {attack_pattern}")
                    print(f"{Fore.GREEN}[PROTECTION] Blocked {src_ip} due to SYN flood attack{Style.RESET_ALL}")
                
                tracker['last_alert'] = current_time
                
                # Increment stats with more detailed breakdown
                with self.stats_lock:
                    if 'attack_types' not in self.stats:
                        self.stats['attack_types'] = {}
                    if 'syn_flood_patterns' not in self.stats['attack_types']:
                        self.stats['attack_types']['syn_flood_patterns'] = {}
                    
                    pattern_key = attack_pattern.split()[0].lower()
                    self.stats['attack_types']['syn_flood_patterns'][pattern_key] = \
                        self.stats['attack_types']['syn_flood_patterns'].get(pattern_key, 0) + 1
                    
                    self.stats['syn_floods'] = self.stats.get('syn_floods', 0) + 1
                    
            # Clean up old counts if needed but maintain intelligence
            if current_time - tracker['first_seen'] > self.syn_flood_timeout:
                # Only reset if the attack isn't ongoing based on rate
                if detection_results['medium']['count'] < 10:
                    # Keep attack history but reset counters
                    previous_pattern = tracker.get('attack_pattern', '')
                    previous_severity = tracker.get('severity_level', 0)
                    previous_peak_rate = tracker.get('peak_rate', 0)
                    
                    tracker['first_seen'] = current_time
                    tracker['count'] = 1
                    tracker['ports'] = set([dst_port])
                    tracker['repeat_ports'] = {dst_port: 1}
                    tracker['syn_rate'] = [current_time]
                    
                    # Preserve attack intelligence
                    if previous_pattern:
                        tracker['historical_attacks'] = tracker.get('historical_attacks', []) + [{
                            'timestamp': current_time,
                            'pattern': previous_pattern,
                            'severity': previous_severity,
                            'peak_rate': previous_peak_rate
                        }]
                    
    def _check_port_scan(self, src_ip, dst_ip, dst_port, current_time):
        """Check for port scanning activity"""
        with self.syn_lock:
            # Create tracker for source IP if it doesn't exist
            if src_ip not in self.syn_tracker:
                self.syn_tracker[src_ip] = {
                    'count': 0,
                    'ports': set(),
                    'first_seen': current_time,
                    'syn_rate': [],
                    'repeat_ports': {}
                }
            
            # Update tracking
            tracker = self.syn_tracker[src_ip]
            tracker['count'] += 1
            tracker['ports'].add(dst_port)
            
            # Track SYN rate with sliding window
            tracker['syn_rate'].append(current_time)
            if len(tracker['syn_rate']) > 20:  # Limit this to avoid excessive memory usage
                tracker['syn_rate'] = tracker['syn_rate'][-20:]
            
            # Track repeated SYNs to the same port
            if dst_port in tracker['repeat_ports']:
                tracker['repeat_ports'][dst_port] += 1
            else:
                tracker['repeat_ports'][dst_port] = 1
                
            # Check for port scanning
            scan_window = 5  # 5 seconds
            rate_threshold = 20  # 20 SYNs within scan window is suspicious
            syn_count_in_window = sum(1 for t in tracker['syn_rate'] if current_time - t <= scan_window)
            
            if (syn_count_in_window >= rate_threshold and 
                    tracker['count'] > 50 and 
                    current_time - tracker.get('last_alert', 0) > 60):  # Rate limit alerts
                # Potential port scanning detected
                alert_msg = f"Potential port scanning from {src_ip}: {tracker['count']} SYNs in {scan_window}s to {len(tracker['ports'])} ports"
                self.alert(alert_msg, src_ip, 'port_scan', severity=2)
                tracker['last_alert'] = current_time
                
                if self.protection_level >= 2:
                    self.block_ip(src_ip, "Port scanning")
                    
            # Clean up old counts if needed
            if current_time - tracker['first_seen'] > self.syn_flood_timeout:
                # Only reset if the attack isn't ongoing based on rate
                if syn_count_in_window < 10:
                    tracker['first_seen'] = current_time
                    tracker['count'] = 1
                    tracker['ports'] = set([dst_port])
                    tracker['repeat_ports'] = {dst_port: 1}
    def _check_tcp_flags(self, flags, src_ip, dst_ip, current_time):
        """Check TCP flags for suspicious patterns (NULL, XMAS, FIN scans)"""
        # NULL scan: no flags set
        is_null_scan = flags == 0
        
        # XMAS scan: FIN, PSH, URG flags set
        is_xmas_scan = flags & 0x29 == 0x29
        
        # FIN scan: only FIN flag set
        is_fin_scan = flags == 0x01
        
        if is_null_scan or is_xmas_scan or is_fin_scan:
            # Track this source
            with self.tcp_flags_lock:
                if src_ip not in self.tcp_flags_tracker:
                    self.tcp_flags_tracker[src_ip] = {
                        'count': 0,
                        'first_seen': current_time,
                        'null_count': 0,
                        'xmas_count': 0,
                        'fin_count': 0
                    }
                
                # Update counts
                tracker = self.tcp_flags_tracker[src_ip]
                tracker['count'] += 1
                
                if is_null_scan:
                    tracker['null_count'] += 1
                    scan_type = "NULL"
                elif is_xmas_scan:
                    tracker['xmas_count'] += 1
                    scan_type = "XMAS"
                else:  # FIN scan
                    tracker['fin_count'] += 1
                    scan_type = "FIN"
                
                # Alert if we've seen enough suspicious packets
                if (tracker['count'] >= 5 and
                        current_time - tracker.get('last_alert', 0) > 60):  # Rate limit alerts
                    alert_msg = f"{scan_type} scan detected from {src_ip}"
    def is_tor_running(self):
        """Check if Tor is running on the system
        Returns:
            tuple: (bool, str) - (is_tor_running, tor_service_info)
        """
        try:
            # Method 1: Check for Tor service process
            tor_processes = []
            try:
                # Check using ps command
                ps_output = subprocess.check_output(["ps", "aux"], text=True)
                for line in ps_output.splitlines():
                    if "tor" in line.lower() and not "grep" in line.lower():
                        tor_processes.append(line)
            except Exception as e:
                logging.debug(f"Error checking tor processes: {str(e)}")
                
            # Method 2: Check for Tor ports
            tor_ports = [9050, 9051]  # Common Tor SOCKS and control ports
            open_tor_ports = []
            
            for port in tor_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)
                        result = s.connect_ex(('127.0.0.1', port))
                        if result == 0:
                            open_tor_ports.append(port)
                except Exception:
                    pass
                    
            # Method 3: Check for Tor service status
            tor_service = False
            try:
                # Try using systemctl (Linux)
                service_output = subprocess.check_output(["systemctl", "status", "tor"], text=True, stderr=subprocess.STDOUT)
                if "active (running)" in service_output.lower():
                    tor_service = True
            except Exception:
                # Ignore errors if systemctl isn't available
                pass
                
            is_tor_running = bool(tor_processes or open_tor_ports or tor_service)
            
            # Build information string
            info = []
            if tor_processes:
                info.append(f"Tor processes found: {len(tor_processes)}")
            if open_tor_ports:
                info.append(f"Tor ports open: {', '.join(map(str, open_tor_ports))}")
            if tor_service:
                info.append("Tor service is active")
                
            return is_tor_running, ", ".join(info) if info else "Unknown (detection method failed)"
            
        except Exception as e:
            logging.debug(f"Error in Tor detection: {str(e)}")
            return False, "Error during detection"
            
    def start_protection(self):
        if not self.interface:
            print(f"{Fore.RED}Error: No network interface selected!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Please select a network interface first (Option 8).{Style.RESET_ALL}")
            input("\nPress Enter to return to main menu...")
            return False

        if not self.is_running:
            try:
                # Check for Tor network before starting
                tor_running, tor_info = self.is_tor_running()
                if tor_running:
                    print(f"{Fore.RED} WARNING: Tor network appears to be running on this system! {Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Using OpenMammoth with Tor may cause iptables conflicts and connection issues.{Style.RESET_ALL}")
                    
                    # Ask user for confirmation
                    confirmation = input(f"\n{Fore.CYAN}Do you want to continue anyway? (y/N): {Style.RESET_ALL}").lower()
                    if confirmation != 'y':
                        print(f"{Fore.YELLOW}Protection startup cancelled by user.{Style.RESET_ALL}")
                        return False
                        
                    print(f"\n{Fore.YELLOW}Proceeding with OpenMammoth startup despite Tor detection...{Style.RESET_ALL}")
                    logging.warning(f"Starting OpenMammoth with Tor running detected.")
                
                # Create a packet executor if not already present
                # This ensures we always have a thread pool for packet processing
                if not hasattr(self, 'packet_executor') or self.packet_executor is None:
                    # Create a larger thread pool for faster packet processing
                    self.packet_executor = ThreadPoolExecutor(max_workers=20)
                    logging.info(f"Created packet processing thread pool with 20 workers")
                
                # Optimize packet capture settings
                # 1. Set a reasonable timeout for Scapy sniff function
                # 2. Use proper filter to reduce packet load (instead of processing everything)
                # 3. Adjust store parameter to reduce memory usage
                
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
                        
                        # Optimize packet capture for performance
                        # - store=False: No packets stored in memory
                        # - filter="ip": Only process IP packets (reduces CPU load)
                        # - timeout=1: Process in small batches to avoid blocking
                        
                        # Performance monitoring
                        last_packet_count = 0
                        last_time = time.time()
                        performance_check_interval = 30  # seconds
                        
                        # Main packet capture loop - processed in small timeouts
                        # to avoid freezing and allow for regular cleanup
                        while self.is_running:
                            try:
                                # Capture in small batches with timeout
                                sniff(iface=self.interface, 
                                     prn=self.packet_handler, 
                                     store=False,  # Never store packets in memory
                                     filter="ip",  # Only capture IP packets
                                     timeout=1)    # Process 1 second at a time
                                
                                # Performance monitoring - log packet rate every 30 seconds
                                current_time = time.time()
                                if current_time - last_time > performance_check_interval:
                                    with self.stats_lock:
                                        current_count = self.stats['total_packets']
                                    
                                    # Calculate packets per second
                                    packets_captured = current_count - last_packet_count
                                    duration = current_time - last_time
                                    packet_rate = packets_captured / duration
                                    
                                    # Log performance metrics
                                    logging.info(f"Performance: {packet_rate:.2f} packets/sec over {duration:.1f}s")
                                    last_packet_count = current_count
                                    last_time = current_time
                                
                            except Exception as loop_err:
                                logging.debug(f"Packet capture iteration error: {str(loop_err)}")
                                # Small sleep to avoid tight loop in case of persistent errors
                                time.sleep(0.1)
                                
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

    def _setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown"""
        try:
            import signal
            
            # Define the signal handler for SIGINT (Ctrl+C) and SIGTERM
            def signal_handler(sig, frame):
                print(f"\n{Fore.YELLOW}Signal {sig} received. Shutting down gracefully...{Style.RESET_ALL}")
                logging.info(f"Signal {sig} received. Shutting down gracefully...")
                self.stop_protection()
                sys.exit(0)
            
            # Register the signal handlers
            signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
            signal.signal(signal.SIGTERM, signal_handler)  # Termination signal
            
            # On Unix systems, handle SIGHUP as well
            if hasattr(signal, 'SIGHUP'):
                signal.signal(signal.SIGHUP, signal_handler)  # Terminal closed
                
            logging.info("Signal handlers registered successfully")
        except Exception as e:
            logging.error(f"Error setting up signal handlers: {str(e)}")
            print(f"{Fore.RED}Warning: Could not set up signal handlers: {str(e)}{Style.RESET_ALL}")
            
    def block_ip(self, ip, reason="Unknown"):
        """Add an IP to the blacklist"""
        try:
            if ip not in getattr(self, 'blacklist', []):
                self.blacklist.append(ip)
                logging.warning(f"Added {ip} to blacklist: {reason}")
                # Print to console for immediate visibility
                print(f"{Fore.RED}[ALERT] Blocked {ip}: {reason}{Style.RESET_ALL}")
                
                with self.stats_lock:
                    if 'ips_blocked' not in self.stats:
                        self.stats['ips_blocked'] = 0
                    self.stats['ips_blocked'] += 1
                return True
            else:
                # Already blocked
                return False
        except Exception as e:
            logging.error(f"Error blocking IP {ip}: {str(e)}")
            return False
            
    def stop_protection(self):
        """Stop packet capture and all monitoring threads"""
        if self.is_running:
            self.is_running = False
            print(f"{Fore.YELLOW}Stopping protection...{Style.RESET_ALL}")
            
            # Close sniffer and wait for threads to finish
            if hasattr(self, 'capture_thread') and self.capture_thread and self.capture_thread.is_alive():
                try:
                    if hasattr(self, 'sniffer'):
                        try:
                            self.sniffer.stop()
                        except Exception as e:
                            logging.error(f"Error stopping sniffer: {str(e)}")
                    self.capture_thread.join(5)
                except Exception as e:
                    logging.error(f"Error stopping capture thread: {str(e)}")
            
            # Ensure thread pool is properly shut down
            if hasattr(self, 'thread_pool'):
                try:
                    self.thread_pool.shutdown(wait=True)  # Wait for all tasks to complete
                    logging.info("Thread pool shutdown successfully")
                except Exception as e:
                    logging.error(f"Error shutting down thread pool: {str(e)}")
            
            # Wait for other threads
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
            
            # Properly shutdown thread pool executor with a timeout
            if hasattr(self, 'thread_pool'):
                try:
                    logging.info("Shutting down thread pool...")
      
                    if sys.version_info >= (3, 9):
                        self.thread_pool.shutdown(wait=True, cancel_futures=True)
                    else:
                        self.thread_pool.shutdown(wait=True)
                    logging.info("Thread pool shutdown complete")
                except Exception as pool_err:
                    logging.error(f"Error shutting down thread pool: {str(pool_err)}")
            
            # Cleanup ALL iptables rules including blacklisted IPs
            for ip in list(self.blocked_ips.keys()):
                try:
                    logging.info(f"Removing iptables rule for {ip}")
                    subprocess.run(
                        ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                        capture_output=True, text=True, check=False
                    )
                    del self.blocked_ips[ip]
                except Exception as e:
                    logging.error(f"Error removing iptables rule for {ip}: {str(e)}")
            
            # Additionally clean any potential OpenMammoth chain rules
            try:
                # Check if our chain exists
                result = subprocess.run(
                    ['iptables', '-L', 'OPENMAMMOTH', '-n'], 
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0:  # Chain exists
                    # Flush the chain
                    subprocess.run(['iptables', '-F', 'OPENMAMMOTH'], check=False)
                    # Remove reference from INPUT chain
                    subprocess.run(['iptables', '-D', 'INPUT', '-j', 'OPENMAMMOTH'], check=False)
                    # Delete the chain
                    subprocess.run(['iptables', '-X', 'OPENMAMMOTH'], check=False)
                    logging.info("Removed OpenMammoth iptables chain")
            except Exception as e:
                logging.error(f"Error cleaning up iptables chains: {str(e)}")
            
            # Log cleanup summary
            logging.info(f"Cleaned up all {len(self.blocked_ips)} iptables rules")
            self.blocked_ips = {}
            
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
            os.system('clear')
            print(f"\n{Fore.CYAN}=== Settings ==={Style.RESET_ALL}")
            print(f"1. Protection Level (Current: {self.protection_level})")
            print(f"2. Advanced Protection (Current: {'Enabled' if self.advanced_protection else 'Disabled'})")
            print(f"3. Debug Mode (Current: {'Enabled' if self.debug_mode else 'Disabled'})")
            print(f"4. Network Interface (Current: {self.interface if self.interface else 'Not selected'})")
            print(f"5. Threat Intelligence (Current: {'Enabled' if self.use_threat_intel else 'Disabled'})")
            print(f"6. Auto Updates (Current: {'Enabled' if self.auto_update else 'Disabled'})")
            print(f"7. Honeypot Detection (Current: {'Enabled' if self.honeypot_enabled else 'Disabled'})")
            print(f"8. Reset IPTables Rules")
            print("9. Back to Main Menu")
            
            choice = input("\nEnter your choice (1-9): ")
            
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
                self.honeypot_enabled = not self.honeypot_enabled
                self.save_config()
                status = "enabled" if self.honeypot_enabled else "disabled"
                print(f"{Fore.GREEN}Honeypot detection {status}{Style.RESET_ALL}")
                if self.honeypot_enabled:
                    print(f"{Fore.YELLOW}\nConfigured honeypot ports: {', '.join(str(p) for p in self.honeypot_ports)}{Style.RESET_ALL}")
                    print("These ports will be monitored for connection attempts.")
                    print("Warning: Ensure these ports are not used by legitimate services")
                    print("on your system to avoid false positives.")
                input("\nPress Enter to continue...")
            elif choice == "8":
                self.reset_iptables_rules()
            elif choice == "9":
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
            
            # Basic statistics
            print(f"\n{Fore.GREEN}=== Basic Statistics ==={Style.RESET_ALL}")
            print(f"Total Packets: {self.stats['total_packets']}")
            print(f"Blocked Packets: {self.stats['blocked_packets']}")
            print(f"Attacks Detected: {self.stats['attacks_detected']}")
            
            # Attack statistics with details
            print(f"\n{Fore.YELLOW}=== Attack Statistics ==={Style.RESET_ALL}")
            print(f"Port Scans: {self.stats['port_scans']}")
            
            # Enhanced SYN flood statistics
            syn_floods = self.stats.get('syn_floods', 0)
            print(f"SYN Floods: {syn_floods}")
            
            # Show detailed SYN flood pattern breakdown if available
            if 'attack_types' in self.stats and 'syn_flood_patterns' in self.stats['attack_types']:
                patterns = self.stats['attack_types']['syn_flood_patterns']
                if patterns:
                    print(f"  ├─ {'SYN Flood Patterns':30}")
                    for pattern_name, count in patterns.items():
                        print(f"  │  ├─ {pattern_name.title():20}: {count}")
            
            # Other attack types
            print(f"UDP Floods: {self.stats['udp_floods']}")
            print(f"ICMP Floods: {self.stats['icmp_floods']}")
            print(f"DNS Amplification: {self.stats['dns_amplification']}")
            print(f"Fragment Attacks: {self.stats['fragment_attacks']}")
            print(f"Malformed Packets: {self.stats['malformed_packets']}")
            print(f"Spoofed IPs: {self.stats['spoofed_ips']}")
            
            # IP-based blocks
            print(f"\n{Fore.MAGENTA}=== Block Statistics ==={Style.RESET_ALL}")
            print(f"Threat Intel Blocks: {self.stats['threat_intel_blocks']}")
            print(f"Reputation Blocks: {self.stats['reputation_blocks']}")
            print(f"Blacklisted IPs: {len(self.blacklist)}")
            print(f"Currently Blocked IPs: {len(self.blocked_ips)}")
            
            # Active connections
            if self.is_running:
                print(f"\n{Fore.BLUE}=== Network Status ==={Style.RESET_ALL}")
                print(f"Active connections: {len(self.connection_tracker)}")
                
                # Show most active IPs if available
                if hasattr(self, 'syn_tracker') and self.syn_tracker:
                    print(f"\n{Fore.CYAN}=== Most Active Source IPs ==={Style.RESET_ALL}")
                    active_ips = sorted([(ip, data['count']) for ip, data in self.syn_tracker.items()], 
                                       key=lambda x: x[1], reverse=True)[:5]
                    for i, (ip, count) in enumerate(active_ips, 1):
                        print(f"{i}. {ip} - {count} packets")
            
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
        print("- Real-time packet analysis with multi-threading support")
        print("- Thread-safe data processing for high-concurrency environments")
        print("- Multiple protection levels with intelligent false positive reduction")
        print("- Advanced attack detection with context-aware analysis")
        print("- IP blocking system with whitelist protection")
        print("- Detailed statistics and comprehensive monitoring")
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
        print("- Intelligent port scan detection with reduced false positives")
        print("- SYN flood protection with legitimate connection detection")
        print("\nFalse Positive Reduction:")
        print("- Pattern-based traffic analysis to identify legitimate services")
        print("- Context-aware traffic evaluation for common usage patterns")
        print("- Connection tracking to identify established legitimate sessions")
        print("- Port pattern recognition for normal service discovery")
        print("- Adaptive thresholds based on traffic history")
        print("\nThread Safety:")
        print("- Fine-grained locking for shared data structures")
        print("- Protected concurrent access to packet tracking information")
        print("- Thread pool executor for parallel packet processing")
        print("- Memory-efficient data structures with automatic cleanup")
        print("\nThreat Intelligence:")
        print("When enabled, OpenMammoth uses external threat intelligence")
        print("to identify and block known malicious IP addresses.")
        print("\nFor more information, visit the GitHub repository.")
        
        input("\nPress Enter to return to main menu...")

    def show_about(self):
        print(f"\n{Fore.CYAN}=== About OpenMammoth ==={Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Version: 2.1{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Author: root0emir{Style.RESET_ALL}")
        print(f"{Fore.BLUE}License: MIT{Style.RESET_ALL}")
        print("\nOpenMammoth is a powerful network protection tool designed to")
        print("secure your system against various types of cyber attacks.")
        print("This version is a OpenMammoth Securonis Edition Forked and optimized for Securonis Linux ")
        print("\nFeatures:")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Real-time packet analysis with multi-threading support")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Thread-safe data structures for concurrent processing")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Multiple protection levels with false positive reduction")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Advanced attack detection with context awareness")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} IP blocking with intelligent service recognition")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Detailed statistics and system impact monitoring")
        print(f"{Fore.GREEN}✓{Style.RESET_ALL} Customizable settings with graceful resource management")
        print("\nNew in Version 2.1:")
        print(f"{Fore.CYAN}•{Style.RESET_ALL} Thread-safe data access with proper locking mechanisms")
        print(f"{Fore.CYAN}•{Style.RESET_ALL} Intelligent SYN flood detection with reduced false positives")
        print(f"{Fore.CYAN}•{Style.RESET_ALL} Context-aware port scan detection")
        print(f"{Fore.CYAN}•{Style.RESET_ALL} Service pattern recognition to whitelist legitimate traffic")
        print(f"{Fore.CYAN}•{Style.RESET_ALL} Memory optimization with adaptive data cleanup")
        print("\nSupported Attack Types:")
        print(f"{Fore.RED}•{Style.RESET_ALL} Port Scanning (with improved accuracy)")
        print(f"{Fore.RED}•{Style.RESET_ALL} SYN Flood (with reduced false positives)")
        print(f"{Fore.RED}•{Style.RESET_ALL} UDP Flood")
        print(f"{Fore.RED}•{Style.RESET_ALL} ICMP Flood")
        print(f"{Fore.RED}•{Style.RESET_ALL} DNS Amplification")
        print(f"{Fore.RED}•{Style.RESET_ALL} Fragment Attacks")
        print(f"{Fore.RED}•{Style.RESET_ALL} Malformed Packets")
        print(f"{Fore.RED}•{Style.RESET_ALL} IP Spoofing")
        print(f"{Fore.RED}•{Style.RESET_ALL} Application Layer Attacks")
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
        
    def is_blacklisted_ip(self, packet):
        """Check if a packet's source IP is in the blacklist"""
        if packet.haslayer('IP'):
            src_ip = packet.getlayer('IP').src
            return self.is_ip_in_blacklist(src_ip)
        return False

    def is_ip_in_whitelist(self, ip):
        """Check if IP is in whitelist"""
        return ip in self.whitelist

    def is_ip_in_threat_intel(self, ip):
        """Check if IP is in threat intelligence database"""
        return ip in self.threat_intel_db

    def check_ip_reputation(self, ip):
        """Gelişmiş IP itibar kontrolü ve tehdit istihbaratı entegrasyonu"""
        # Initialize reputation tracking if not exists
        if not hasattr(self, 'reputation_cache'):
            self.reputation_cache = {}
            self.high_risk_countries = ['KP', 'IR', 'RU', 'CN']  # Example high-risk countries
            self.use_external_threat_api = self.advanced_protection  # Only use external APIs in advanced mode
        
        # Skip checking local IPs and whitelisted IPs
        if self.is_local_network(ip) or self.is_ip_in_whitelist(ip):
            return False
        
        # Check if it's in the blacklist (instant block)
        if self.is_ip_in_blacklist(ip):
            self.stats['reputation_blocks'] += 1
            if ip not in self.reputation_cache:
                self.reputation_cache[ip] = {
                    'score': 100,  # Maximum score
                    'last_check': time.time(),
                    'reasons': ['Manual blacklist'],
                    'source': 'local'
                }
            return True
        
        current_time = time.time()
        
        # Check if we have a cached result that's still valid (30 minute cache)
        if ip in self.reputation_cache:
            # Only use cache if it's less than 30 minutes old
            if current_time - self.reputation_cache[ip]['last_check'] < 1800:  # 30 minutes
                if self.reputation_cache[ip]['score'] >= 80:  # Very high risk
                    self.stats['reputation_blocks'] += 1
                    return True
                return False
        
        # Initialize reputation score and evidence
        rep_score = 0
        reasons = []
        
        # Layer 1: Check local threat database
        if self.use_threat_intel and self.is_ip_in_threat_intel(ip):
            self.stats['threat_intel_blocks'] += 1
            threat_info = self.threat_intel_db.get(ip, {'score': 80, 'reason': 'Known malicious'})
            rep_score += min(90, threat_info.get('score', 80))  # Cap at 90
            reasons.append(f"Threat DB: {threat_info.get('reason', 'Known malicious')}")
        
        # Layer 2: Check IP reputation database
        if hasattr(self, 'ip_reputation_db') and ip in self.ip_reputation_db:
            reputation = self.ip_reputation_db[ip]
            rep_score = max(rep_score, min(85, reputation.get('score', 0)))
            if 'category' in reputation:
                reasons.append(f"Rep DB: {reputation['category']}")
        
        # Layer 3: Analyze behavior history if available
        if hasattr(self, 'connection_tracker'):
            conn_key_prefix = f"{ip}-"
            conn_count = 0
            rejected_count = 0
            ports = set()
            
            # Count connections from this IP
            for key, data in self.connection_tracker.items():
                if key.startswith(conn_key_prefix):
                    conn_count += data.get('count', 0)
                    if 'rejected' in data and data['rejected']:
                        rejected_count += 1
                    # Extract destination port if available
                    parts = key.split('-')
                    if len(parts) > 2 and ':' in parts[1]:
                        try:
                            port = int(parts[1].split(':')[1])
                            ports.add(port)
                        except:
                            pass
            
            # Check connection rate
            if conn_count > 1000:  # Very high connection rate
                rep_score += 30
                reasons.append("High connection rate")
            elif conn_count > 500:
                rep_score += 15
                reasons.append("Elevated connection rate")
            
            # Check rejected connection attempts
            if rejected_count > 20:
                rep_score += 25
                reasons.append("Multiple rejected connections")
            
            # Check for suspicious port access patterns
            if len(ports) > 100:  # Accessing many different ports
                rep_score += 20
                reasons.append("Unusual port access pattern")
        
        # Layer 4: Check for network scanning behavior
        if hasattr(self, 'port_scan_tracker') and ip in self.port_scan_tracker:
            scan_data = self.port_scan_tracker[ip]
            if scan_data.get('scan_detection_count', 0) > 0:
                scan_penalty = min(40, scan_data.get('scan_detection_count', 0) * 10)
                rep_score += scan_penalty
                reasons.append(f"Port scanning activity ({scan_data.get('scan_detection_count', 0)} instances)")
        
        # Layer 5: Geographic location check (if available)
        if hasattr(self, 'geo_db') and ip in getattr(self, 'geo_db', {}):
            country = self.geo_db[ip].get('country', '')
            if country in self.high_risk_countries:
                rep_score += 15
                reasons.append(f"High-risk country: {country}")
            
        # Layer 6: Check behavioral markers
        attack_markers = 0
        
        # Check TTL anomalies
        if hasattr(self, 'ttl_tracker') and ip in self.ttl_tracker:
            ttl_data = self.ttl_tracker[ip]
            if len(ttl_data.get('values', [])) >= 3:
                # Calculate standard deviation
                ttl_values = ttl_data['values'][-10:]  # Last 10 values
                avg = sum(ttl_values) / len(ttl_values)
                variance = sum((x - avg) ** 2 for x in ttl_values) / len(ttl_values)
                std_dev = variance ** 0.5
                
                if std_dev > 5:
                    attack_markers += 1
                    rep_score += 15
                    reasons.append("TTL manipulation detected")
        
        # Check TCP sequence anomalies
        if hasattr(self, 'seq_tracker') and ip in self.seq_tracker:
            seq_data = self.seq_tracker[ip]
            if seq_data.get('prediction_attempts', 0) > 0:
                attack_markers += 1
                rep_score += 20
                reasons.append("TCP sequence anomalies")
        
        # Malformed packet history
        if hasattr(self, 'malformed_packet_history') and ip in getattr(self, 'malformed_packet_history', {}):
            malformed_count = self.malformed_packet_history[ip].get('count', 0)
            if malformed_count > 3:
                attack_markers += 1
                rep_score += min(25, malformed_count * 5)
                reasons.append(f"Malformed packets ({malformed_count})")
        
        # Fragment attack history
        if hasattr(self, 'fragment_attack_history') and ip in getattr(self, 'fragment_attack_history', {}):
            frag_count = self.fragment_attack_history[ip].get('count', 0)
            if frag_count > 0:
                attack_markers += 1
                rep_score += min(30, frag_count * 10)
                reasons.append(f"Fragment attacks ({frag_count})")
        
        # If we have multiple attack markers, increase reputation impact
        if attack_markers >= 2:
            rep_score += 20
            reasons.append("Multiple attack signatures")
        
        # Store the result in cache
        self.reputation_cache[ip] = {
            'score': rep_score,
            'last_check': current_time,
            'reasons': reasons,
            'source': 'composite'
        }
        
        # Return decision based on reputation score
        # Very high risk IPs are automatically blocked
        if rep_score >= 80:
            logging.warning(f"High-risk IP detected ({ip}): {rep_score}/100 - {', '.join(reasons)}")
            self.stats['reputation_blocks'] += 1
            return True
        
        # Log suspicious but not blocked IPs
        if rep_score >= 50:
            logging.info(f"Suspicious IP detected ({ip}): {rep_score}/100 - {', '.join(reasons)}")
        
        return False

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

    def check_root_permissions(self):
        """Check if the script is running with root/administrator privileges"""
        try:
            # Unix (Linux/MacOS) - check for effective user ID 0 (root)
            if os.name == 'posix':
                return os.geteuid() == 0
            # Windows - attempt to access a privileged file
            elif os.name == 'nt':
                try:
                    # Try to open a system file that requires admin privileges
                    temp = open(os.path.join(os.environ.get('windir', 'C:\\Windows'), 'system.ini'), 'a')
                    temp.close()
                    return True
                except PermissionError:
                    return False
            return False  # Default for unknown OS
        except Exception as e:
            logging.error(f"Error checking root permissions: {str(e)}")
            return False

    def check_system_requirements(self):
        """Check basic system requirements"""
        # Check for required packages
        try:
            # Check Scapy functionality
            if not hasattr(scapy, 'all'):
                print(f"{Fore.RED}Error: Scapy not fully functional{Style.RESET_ALL}")
                sys.exit(1)
                
            # Check for iptables on Linux
            if os.name == 'posix':
                try:
                    subprocess.run(['iptables', '--version'], 
                                  stdout=subprocess.PIPE, 
                                  stderr=subprocess.PIPE, 
                                  check=True)
                except (subprocess.SubprocessError, FileNotFoundError):
                    print(f"{Fore.YELLOW}Warning: iptables not found. Some protection features will be limited.{Style.RESET_ALL}")
                    logging.warning("iptables not found. Some protection features will be limited.")
        except Exception as e:
            logging.error(f"Error checking system requirements: {str(e)}")
            print(f"{Fore.RED}Error checking system requirements: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

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
            
            # Basic status information
            print(f"\n{Fore.GREEN}[+] Protection Status: ACTIVE{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Interface: {self.interface}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Protection Level: {self.protection_level}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Advanced Protection: {'Enabled' if self.advanced_protection else 'Disabled'}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Threat Intelligence: {'Enabled' if self.use_threat_intel else 'Disabled'}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Uptime: {int(hours)}h {int(minutes)}m {int(seconds)}s{Style.RESET_ALL}")
            
            # Enhanced protection modules status
            print(f"\n{Fore.MAGENTA}=== Active Protection Modules ==={Style.RESET_ALL}")
            protection_modules = [
                ("SYN Flood Detection", "Enhanced"),
                ("DoS Protection", "Active"),
                ("Port Scan Detection", "Active"),
                ("IP Reputation", "Active" if self.use_threat_intel else "Disabled"),
                ("Blacklist Enforcement", "Active"),
                ("Packet Filtering", "Active")
            ]
            
            for module, status in protection_modules:
                status_color = Fore.GREEN if status in ["Active", "Enhanced"] else Fore.YELLOW
                print(f"{Fore.BLUE}[*] {module}: {status_color}{status}{Style.RESET_ALL}")
            
            # Current statistics summary
            print(f"\n{Fore.YELLOW}=== Current Statistics ==={Style.RESET_ALL}")
            print(f"Total Packets: {self.stats['total_packets']}")
            print(f"Blocked Packets: {self.stats['blocked_packets']}")
            print(f"Attacks Detected: {self.stats['attacks_detected']}")
            
            # Attack breakdown
            attacks = [
                ("SYN Floods", self.stats.get('syn_floods', 0)),
                ("UDP Floods", self.stats.get('udp_floods', 0)),
                ("ICMP Floods", self.stats.get('icmp_floods', 0)),
                ("Port Scans", self.stats.get('port_scans', 0))
            ]
            
            if any(count > 0 for _, count in attacks):
                print(f"\n{Fore.RED}=== Attack Breakdown ==={Style.RESET_ALL}")
                for attack_type, count in attacks:
                    if count > 0:
                        print(f"{Fore.RED}[!] {attack_type}: {count}{Style.RESET_ALL}")
            
            # Block information
            print(f"\n{Fore.CYAN}=== Block Information ==={Style.RESET_ALL}")
            print(f"Blacklisted IPs: {len(self.blacklist)}")
            print(f"Temporary Blocks: {len(self.blocked_ips) - len(self.blacklist)}")
            print(f"Total Active Blocks: {len(self.blocked_ips)}")
            
            # Recent alerts summary if available
            if hasattr(self, 'recent_alerts') and self.recent_alerts:
                print(f"\n{Fore.YELLOW}=== Recent Alerts ==={Style.RESET_ALL}")
                for i, alert in enumerate(self.recent_alerts[:3], 1):
                    timestamp, alert_type, message = alert
                    alert_time = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
                    print(f"{i}. [{alert_time}] {Fore.RED}{alert_type}{Style.RESET_ALL}: {message}")
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

    def check_application_layer_attacks(self, packet):
        """Detect application layer attacks like SQLi, XSS, Path Traversal in HTTP/HTTPS traffic"""
        if not TCP in packet:
            return False
            
        # Check if this is HTTP/HTTPS traffic
        tcp_dport = packet[TCP].dport
        tcp_sport = packet[TCP].sport
        ip_src = packet[IP].src
        
        # HTTP/HTTPS ports
        http_ports = [80, 8080, 8000, 8008, 8088]
        https_ports = [443, 8443, 4443]
        
        is_http = (tcp_dport in http_ports) or (tcp_sport in http_ports)
        is_https = (tcp_dport in https_ports) or (tcp_sport in https_ports)
        
        if not (is_http or is_https):
            return False
        
        # Initialize attack signature database if needed
        if not hasattr(self, 'http_attack_signatures'):
            # Common attack signatures for SQLi, XSS, path traversal, etc.
            self.http_attack_signatures = {
                'sqli': [
                    b"' OR 1=1", b"' OR '1'='1", b"--", b";--", b"/*", b"*/", 
                    b"UNION SELECT", b"SELECT FROM", b"DROP TABLE", b"INSERT INTO",
                    b"1=1", b"OR 1=1", b"OR true", b"' OR true", b"\\x27 OR",
                    b"admin'--", b"' or #", b"benchmark("
                ],
                'xss': [
                    b"<script>", b"</script>", b"javascript:", b"onerror=", b"onload=",
                    b"eval(", b"document.cookie", b"<img src=x onerror=", b"alert(",
                    b"String.fromCharCode", b"iframe", b"onmouseover="
                ],
                'path_traversal': [
                    b"../", b"..\\\x5c", b"/etc/passwd", b"c:\\\x5cwindows", b"WEB-INF", 
                    b"../..", b"../../../", b"/boot.ini", b"wp-config.php", b"config.php"
                ],
                'command_injection': [
                    b"| ls", b"& ping", b"; whoami", b"|| id", b"& dir", b"; cat ", 
                    b"$(command)", b"`command`", b"; rm -rf", b":(){ :|:& };:"
                ],
                'file_inclusion': [
                    b"php://filter", b"data://", b"zip://", b"phar://", b"file://", 
                    b"gopher://", b"expect://", b"input://"
                ]
            }
            self.http_attacks_detected = {}
        
        # Track per-IP HTTP attack attempts
        if ip_src not in self.http_attacks_detected:
            self.http_attacks_detected[ip_src] = {
                'count': 0,
                'types': set(),
                'last_seen': time.time()
            }
        
        # Raw payload analysis
        raw_payload = bytes(packet[TCP].payload) if TCP in packet else b""
        if not raw_payload and Raw in packet:
            raw_payload = bytes(packet[Raw].load)
            
        if not raw_payload:
            return False
            
        # Deep packet inspection for HTTP attacks
        attack_types = []
        
        # Check for each attack type
        for attack_type, signatures in self.http_attack_signatures.items():
            for signature in signatures:
                if signature.lower() in raw_payload.lower():
                    attack_types.append(attack_type)
                    self.http_attacks_detected[ip_src]['types'].add(attack_type)
                    self.http_attacks_detected[ip_src]['count'] += 1
                    self.http_attacks_detected[ip_src]['last_seen'] = time.time()
                    
                    # Track in stats
                    attack_type_stat = f"{attack_type}_attacks"
                    if attack_type_stat not in self.stats:
                        self.stats[attack_type_stat] = 0
                    self.stats[attack_type_stat] += 1
                    
                    logging.warning(f"Detected {attack_type} attack in HTTP traffic from {ip_src}")
                    print(f"{Fore.RED}[!] {attack_type.upper()} attack detected from {ip_src}{Style.RESET_ALL}")
                    break  # Once we found one signature of this type, move to next type
        
        # Evaluate attack severity
        if attack_types:
            # Multiple attack types or repeated attacks are higher severity
            if len(attack_types) > 1 or self.http_attacks_detected[ip_src]['count'] > 3:
                return True  # Block immediately
            else:
                # For first few attempts, just log but don't block yet
                # This helps reduce false positives
                if self.http_attacks_detected[ip_src]['count'] <= 3:
                    logging.info(f"Potential {'/'.join(attack_types)} attack from {ip_src} (monitoring)")
                    return False
                else:
                    return True
                    
        return False

    def check_unusual_tcp_flags(self, packet):
        """Advanced analysis of TCP flags to detect unusual combinations and stealth techniques"""
        if not TCP in packet:
            return False
        
        # Get TCP flags
        flags = packet[TCP].flags
        ip_src = packet[IP].src
        tcp_dport = packet[TCP].dport
        current_time = time.time()
        
        # Initialize TCP flags tracker if not exists
        if not hasattr(self, 'tcp_flags_tracker'):
            self.tcp_flags_tracker = {}
            
        # Known suspicious flag combinations
        suspicious_combinations = [
            0x29,  # FIN-PSH-URG (XMAS scan)
            0x01,  # FIN only
            0x00,  # NULL scan
            0x40,  # ACK scan
            0x04,  # RST scan
            0x3F   # ALL flags set
        ]
        
        # Track flags from this source
        if ip_src not in self.tcp_flags_tracker:
            self.tcp_flags_tracker[ip_src] = {
                'flags_history': [flags],
                'first_seen': current_time,
                'last_seen': current_time,
                'ports_targeted': {tcp_dport: 1},
                'unusual_combinations': 0
            }
        else:
            tracker = self.tcp_flags_tracker[ip_src]
            tracker['flags_history'].append(flags)
            tracker['last_seen'] = current_time
            
            # Keep history manageable
            if len(tracker['flags_history']) > 20:
                tracker['flags_history'] = tracker['flags_history'][-20:]
                
            # Track targeted ports
            if tcp_dport in tracker['ports_targeted']:
                tracker['ports_targeted'][tcp_dport] += 1
            else:
                tracker['ports_targeted'][tcp_dport] = 1
        
        # Check for direct suspicious combinations
        if flags in suspicious_combinations:
            self.tcp_flags_tracker[ip_src]['unusual_combinations'] += 1
            logging.warning(f"Unusual TCP flags (0x{flags:02X}) detected from {ip_src} to port {tcp_dport}")
            print(f"{Fore.RED}[!] Unusual TCP flags combination detected from: {ip_src}{Style.RESET_ALL}")
            return True
        
        # Check for pattern-based detection
        if len(self.tcp_flags_tracker[ip_src]['flags_history']) >= 5:
            # Track variety of flags used
            unique_flags = set(self.tcp_flags_tracker[ip_src]['flags_history'])
            
            # Many different flag combinations in a short time = suspicious
            if len(unique_flags) >= 3 and len(self.tcp_flags_tracker[ip_src]['ports_targeted']) >= 3:
                time_span = current_time - self.tcp_flags_tracker[ip_src]['first_seen']
                if time_span < 30:  # Within 30 seconds
                    self.tcp_flags_tracker[ip_src]['unusual_combinations'] += 1
                    logging.warning(f"TCP flag manipulation pattern detected from {ip_src}: {len(unique_flags)} combinations")
                    print(f"{Fore.RED}[!] TCP flag manipulation pattern detected from: {ip_src}{Style.RESET_ALL}")
                    return True
        
        # Check high rate of unusual flags
        if hasattr(self.tcp_flags_tracker[ip_src], 'unusual_combinations') and \
           self.tcp_flags_tracker[ip_src]['unusual_combinations'] >= 3:
            logging.warning(f"Persistent TCP flag abuse from {ip_src}: {self.tcp_flags_tracker[ip_src]['unusual_combinations']} instances")
            print(f"{Fore.RED}[!] Persistent TCP flag abuse from: {ip_src}{Style.RESET_ALL}")
            return True
            
        return False

def main():
    if os.geteuid() != 0:
        print(f"{Fore.RED}Error: This program must be run as root.{Style.RESET_ALL}")
        sys.exit(1)
    
    tool = OpenMammoth()
    tool.display_menu()

if __name__ == "__main__":
    main()
