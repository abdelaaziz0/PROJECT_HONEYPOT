import os
import sqlite3
import datetime

SSH_THRESHOLD = 5

def get_malicious_ips():
    conn = sqlite3.connect('honeypot_logs.db')
    c = conn.cursor()
    since_time = (datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat()
    c.execute('''
        SELECT src_ip, COUNT(*) as attempt_count
        FROM ssh_logs
        WHERE timestamp >= ?
        GROUP BY src_ip
        HAVING attempt_count > ?
    ''', (since_time, SSH_THRESHOLD))
    results = c.fetchall()
    conn.close()
    return [ip for ip, count in results]

def block_ip(ip_address):
    check_command = f"sudo iptables -L INPUT -v -n | grep {ip_address}"
    if os.system(check_command) == 0:
        print(f"IP {ip_address} is already blocked.")
        return
    command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    os.system(command)
    print(f"Blocked IP: {ip_address}")

def main():
    malicious_ips = get_malicious_ips()
    for ip in malicious_ips:
        block_ip(ip)

if __name__ == "__main__":
    main()
