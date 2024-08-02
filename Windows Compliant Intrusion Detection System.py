from scapy.all import *
import logging
import numpy as np
import subprocess
import threading
import time
import os
import re
import base64
import binascii

# Configure logging
logging.basicConfig(filename='ids_logs.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables for statistical analysis
packet_sizes = []
packet_count = 0
ip_traffic = {}  # Dictionary to track traffic per IP
suspicious_ips = set()  # Set to track blocked IPs
alert_thresholds = {
    "large_packet_size": 1500,  # Threshold for large packet detection
    "packet_count": 100,        # Threshold for frequent request detection
    "same_size_packet_count": 50  # Threshold for same size packet detection
}

# Configuration
block_enabled = True  # Set to False to disable IP blocking

# Regular expressions for detecting common obfuscation techniques
obfuscation_patterns = {
    "base64": r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    "hex": r"(?:\\x[0-9A-Fa-f]{2})+",
    "unicode": r"(?:\\u[0-9A-Fa-f]{4})+",
    "url_encode": r"%[0-9A-Fa-f]{2}"
}
def print_banner():
    banner = r"""
 ___       _                       _                        
|_ _|_ __ | |_ ___ _ __ _ __   ___| |_ __ _ _ __   ___ _ __ 
 | || '_ \| __/ _ \ '__| '_ \ / _ \ __/ _` | '_ \ / _ \ '__|
 | || | | | ||  __/ |  | | | |  __/ || (_| | | | |  __/ |   
|___|_| |_|\__\___|_|  |_| |_|\___|\__\__,_|_| |_|\___|_|   
                                                            
               Developed by Aryan Parashar
    """
    print(banner)

def block_ip(ip_address):
    """Block IP using Windows firewall (requires administrative privileges)."""
    if block_enabled and ip_address not in suspicious_ips:
        command = f"netsh advfirewall firewall add rule name='Blocked IP {ip_address}' dir=in action=block remoteip={ip_address}"
        try:
            subprocess.run(command, shell=True, check=True)
            suspicious_ips.add(ip_address)
            logging.info(f"IP {ip_address} has been blocked successfully.")
        except Exception as e:
            logging.error(f"Failed to block IP {ip_address}: {e}")

def unblock_ip(ip_address):
    """Unblock an IP using Windows firewall."""
    if block_enabled and ip_address in suspicious_ips:
        command = f"netsh advfirewall firewall delete rule name='Blocked IP {ip_address}' remoteip={ip_address}"
        try:
            subprocess.run(command, shell=True, check=True)
            suspicious_ips.remove(ip_address)
            logging.info(f"IP {ip_address} has been unblocked successfully.")
        except Exception as e:
            logging.error(f"Failed to unblock IP {ip_address}: {e}")

def detect_large_packets(packet_size, ip_src, ip_dst):
    """Detect and log large packets."""
    if packet_size > alert_thresholds["large_packet_size"]:
        logging.warning(f"Large packet ({packet_size} bytes) detected from {ip_src} to {ip_dst}")

def detect_frequent_requests(ip_src):
    """Detect and block frequent requests from a single IP."""
    if ip_traffic[ip_src]['count'] > alert_thresholds["packet_count"]:
        # Check if recent packets have the same size (indicative of an attack)
        if len(set(ip_traffic[ip_src]['sizes'][-alert_thresholds["same_size_packet_count"]:])) == 1:
            logging.warning(f"Frequent and repetitive traffic detected from {ip_src}. Blocking IP.")
            block_ip(ip_src)

def log_packet_statistics():
    """Log packet statistics periodically."""
    while True:
        time.sleep(60)  # Log every 60 seconds
        if packet_count > 0:
            avg_packet_size = np.mean(packet_sizes)
            logging.info(f"Total packets: {packet_count}, Average packet size: {avg_packet_size:.2f} bytes")

def decode_obfuscation(payload):
    """Try to decode common obfuscation techniques in payload."""
    decoded_payloads = []

    # Base64 decoding
    try:
        if re.search(obfuscation_patterns["base64"], payload):
            decoded_payloads.append(base64.b64decode(payload).decode('utf-8', errors='ignore'))
    except binascii.Error:
        pass

    # Hex decoding
    try:
        if re.search(obfuscation_patterns["hex"], payload):
            hex_string = payload.replace("\\x", "")
            decoded_payloads.append(bytes.fromhex(hex_string).decode('utf-8', errors='ignore'))
    except ValueError:
        pass

    # URL decode
    try:
        if re.search(obfuscation_patterns["url_encode"], payload):
            decoded_payloads.append(bytes.fromhex(payload.replace('%', '')).decode('utf-8', errors='ignore'))
    except ValueError:
        pass

    return decoded_payloads

def analyze_payload(packet):
    """Analyze packet payload for malicious content."""
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')

        # Look for common obfuscation patterns
        for pattern_name, pattern in obfuscation_patterns.items():
            if re.search(pattern, payload):
                logging.warning(f"Obfuscated payload detected ({pattern_name} pattern) from {packet[IP].src}")
                decoded_payloads = decode_obfuscation(payload)
                for decoded in decoded_payloads:
                    logging.info(f"Decoded payload: {decoded}")

        # Simple malware signature detection (e.g., strings commonly found in malware)
        malware_signatures = ["eval(", "exec(", "base64_decode(", "powershell ", "cmd.exe", "nc -e", "rm -rf /"]
        for signature in malware_signatures:
            if signature in payload:
                logging.warning(f"Potential malware signature detected ({signature}) from {packet[IP].src}")

def packet_callback(packet):
    """Callback function for processing packets."""
    global packet_sizes, packet_count, ip_traffic

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_size = len(packet)

        # Update packet statistics
        packet_sizes.append(packet_size)
        packet_count += 1

        # Track IP traffic statistics
        if ip_src not in ip_traffic:
            ip_traffic[ip_src] = {'count': 0, 'sizes': []}
        ip_traffic[ip_src]['count'] += 1
        ip_traffic[ip_src]['sizes'].append(packet_size)

        # Detect anomalies
        detect_large_packets(packet_size, ip_src, ip_dst)
        detect_frequent_requests(ip_src)

        # Analyze packet payload for malicious content
        analyze_payload(packet)

def monitor_unblocking():
    """Monitor and unblock IPs after a certain period."""
    unblock_interval = 600  # Unblock IPs after 600 seconds (10 minutes)
    while True:
        time.sleep(unblock_interval)
        for ip in list(suspicious_ips):
            unblock_ip(ip)

def setup_firewall():
    """Set up Windows firewall for IP blocking."""
    if os.name == 'nt':  # Check if the system is Windows
        subprocess.run("netsh advfirewall set allprofiles state on", shell=True, check=False)
        logging.info("Windows firewall is enabled.")
    else:
        logging.warning("IP blocking is only supported on Windows systems.")

# Main function to start packet sniffing
def main():
    """Main function to start packet sniffing."""
    print_banner()
    # Start packet statistics logging thread
    stats_thread = threading.Thread(target=log_packet_statistics)
    stats_thread.daemon = True
    stats_thread.start()

    # Start unblocking monitoring thread
    unblock_thread = threading.Thread(target=monitor_unblocking)
    unblock_thread.daemon = True
    unblock_thread.start()

    # Set up firewall for IP blocking
    setup_firewall()

    # Start sniffing network traffic
    print("Starting packet capture. Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Packet capture stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
