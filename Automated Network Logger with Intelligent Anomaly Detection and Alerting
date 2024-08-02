import time
import logging
import threading
import json
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import *
from collections import defaultdict

# Configure logging
logging.basicConfig(
    filename='network_traffic.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Packet statistics
packet_stats = defaultdict(int)
suspicious_ips = set()  # Store IPs identified as suspicious

# Configuration for packet capture
config = {
    "max_packets": 1000,  # Maximum number of packets to capture
    "log_detail": True,   # Log detailed packet information
    "filter": None,       # Custom filter (e.g., "tcp", "ip", "port 80")
    "monitor_interfaces": None,  # Monitor specific interfaces (None for all)
    "email_alerts": False,  # Enable email alerts for suspicious activity
    "alert_email": "your_email@example.com",  # Recipient email for alerts
    "smtp_server": "smtp.example.com",  # SMTP server for sending emails
    "smtp_port": 587,  # SMTP server port
    "smtp_user": "your_email@example.com",  # SMTP server username
    "smtp_password": "your_password",  # SMTP server password
    "webhook_url": None  # Webhook URL for notifications (e.g., Slack)
}

# Thresholds for alerts
alert_thresholds = {
    "packet_rate": 100,  # Packets per second threshold
    "suspicious_ip_threshold": 10  # Number of packets from a single IP to trigger alert
}

# Lock for thread-safe operations
lock = threading.Lock()

def send_email_alert(subject, body):
    """Send an email alert."""
    try:
        msg = MIMEMultipart()
        msg['From'] = config["smtp_user"]
        msg['To'] = config["alert_email"]
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(config["smtp_server"], config["smtp_port"]) as server:
            server.starttls()
            server.login(config["smtp_user"], config["smtp_password"])
            server.sendmail(config["smtp_user"], config["alert_email"], msg.as_string())

        logging.info("Email alert sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def send_webhook_notification(message):
    """Send a notification to a webhook (e.g., Slack)."""
    if config["webhook_url"]:
        try:
            requests.post(config["webhook_url"], json={"text": message})
            logging.info("Webhook notification sent successfully.")
        except Exception as e:
            logging.error(f"Failed to send webhook notification: {e}")

def detect_anomalies(packet):
    """Detect anomalies in network traffic."""
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src

        # Check for suspicious IP traffic
        with lock:
            packet_stats[src_ip] += 1
            if packet_stats[src_ip] > alert_thresholds["suspicious_ip_threshold"]:
                if src_ip not in suspicious_ips:
                    suspicious_ips.add(src_ip)
                    message = f"Suspicious activity detected from IP: {src_ip}"
                    logging.warning(message)
                    if config["email_alerts"]:
                        send_email_alert("Suspicious IP Detected", message)
                    if config["webhook_url"]:
                        send_webhook_notification(message)

def log_packet_summary(packet):
    """Log packet summary."""
    with lock:
        logging.info(packet.summary())

def log_packet_details(packet):
    """Log detailed packet information."""
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        logging.info(f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}, Protocol: {ip_layer.proto}")

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        logging.info(f"Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        logging.info(f"Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")

    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        logging.info(f"ICMP Type: {icmp_layer.type}, Code: {icmp_layer.code}")

def packet_callback(packet):
    """Callback for processing packets."""
    global packet_stats

    with lock:
        # Increment packet count
        if packet.haslayer(IP):
            packet_stats['IP'] += 1
        if packet.haslayer(TCP):
            packet_stats['TCP'] += 1
        if packet.haslayer(UDP):
            packet_stats['UDP'] += 1
        if packet.haslayer(ICMP):
            packet_stats['ICMP'] += 1

    # Log packet details
    if config["log_detail"]:
        log_packet_summary(packet)
        log_packet_details(packet)

    # Detect anomalies
    detect_anomalies(packet)

    # Check if logging limit is reached
    if sum(packet_stats.values()) >= config["max_packets"]:
        return False

def print_statistics():
    """Print packet statistics."""
    while True:
        with lock:
            stats = json.dumps(packet_stats, indent=4)
            print(f"\nPacket Statistics:\n{stats}\n")
        time.sleep(10)

def main():
    """Start monitoring."""
    # Start statistics printing thread
    stats_thread = threading.Thread(target=print_statistics)
    stats_thread.daemon = True
    stats_thread.start()

    # Start packet sniffing
    print("Starting packet capture. Press Ctrl+C to stop.")
    try:
        sniff(
            iface=config["monitor_interfaces"],
            filter=config["filter"],
            prn=packet_callback,
            store=0
        )
    except KeyboardInterrupt:
        print("Packet capture stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
