import socket
import threading
import sqlite3
import datetime

HOST = '0.0.0.0'
PORT = 2222
conn = sqlite3.connect('honeypot_logs.db', check_same_thread=False)
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS ssh_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        attempted_username TEXT,
        attempted_password TEXT
    )
''')
conn.commit()

def log_attempt(src_ip, username, password):
    timestamp = datetime.datetime.now().isoformat()
    c.execute('INSERT INTO ssh_logs (timestamp, src_ip, attempted_username, attempted_password) VALUES (?, ?, ?, ?)',
              (timestamp, src_ip, username, password))
    conn.commit()
    print(f"[{timestamp}] SSH attempt from {src_ip} with username '{username}' and password '{password}'")

def handle_client(conn_client, addr):
    src_ip = addr[0]
    print(f"Connection from {src_ip}:{addr[1]}")
    try:
        conn_client.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")
        data = conn_client.recv(1024).decode('utf-8').strip()
        if data.startswith("SSH-"):
            pass
        conn_client.sendall(b"Username: ")
        username = conn_client.recv(1024).decode('utf-8').strip()
        conn_client.sendall(b"Password: ")
        password = conn_client.recv(1024).decode('utf-8').strip()
        log_attempt(src_ip, username, password)
        conn_client.sendall(b"Authentication failed.\r\n")
    except Exception as e:
        print(f"Error handling client {src_ip}: {e}")
    finally:
        conn_client.close()

def start_ssh_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"SSH Honeypot listening on {HOST}:{PORT}")
    try:
        while True:
            conn_client, addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn_client, addr))
            client_thread.start()
    except KeyboardInterrupt:
        print("Shutting down SSH Honeypot.")
    finally:
        server.close()
        conn.close()

if __name__ == "__main__":
    start_ssh_honeypot()
