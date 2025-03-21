from scapy.all import sniff
import sqlite3
import datetime

INTERFACES = ["eth0"]
FILTER = "tcp port 2222 or tcp port 8080"

conn = sqlite3.connect('honeypot_logs.db', check_same_thread=False)
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS packet_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        info TEXT
    )
''')
conn.commit()

def log_packet(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto
        info = packet.summary()
        timestamp = datetime.datetime.now().isoformat()
        c.execute("INSERT INTO packet_logs (timestamp, src_ip, dst_ip, protocol, info) VALUES (?, ?, ?, ?, ?)",
                  (timestamp, src_ip, dst_ip, protocol, info))
        conn.commit()
        print(f"[{timestamp}] Packet from {src_ip} to {dst_ip} | Protocol: {protocol} | Info: {info}")

def start_packet_capture():
    print("Starting packet capture...")
    sniff(filter=FILTER, prn=log_packet, iface=INTERFACES, store=0)

if __name__ == "__main__":
    start_packet_capture()
