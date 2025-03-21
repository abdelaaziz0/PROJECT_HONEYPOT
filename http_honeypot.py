import socket
import threading
import sqlite3
import datetime

HOST = '0.0.0.0' 
PORT = 8080

conn = sqlite3.connect('honeypot_logs.db', check_same_thread=False)
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS http_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        request TEXT,
        response TEXT
    )
''')
conn.commit()

def log_http_interaction(src_ip, request, response):
    timestamp = datetime.datetime.now().isoformat()
    c.execute('INSERT INTO http_logs (timestamp, src_ip, request, response) VALUES (?, ?, ?, ?)',
              (timestamp, src_ip, request, response))
    conn.commit()
    print(f"[{timestamp}] HTTP request from {src_ip}: {request}")

def handle_client(conn_client, addr):
    src_ip = addr[0]
    print(f"HTTP connection from {src_ip}:{addr[1]}")
    try:
        request = conn_client.recv(1024).decode('utf-8').strip()
        if not request:
            conn_client.close()
            return
        log_http_interaction(src_ip, request, "200 OK")
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<!DOCTYPE html>"
            "<html lang='en'>"
            "<head>"
            "    <meta charset='UTF-8'>"
            "    <meta http-equiv='X-UA-Compatible' content='IE=edge'>"
            "    <meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "    <title>Admin Panel</title>"
            "    <style>"
            "        body {"
            "            font-family: Arial, sans-serif;"
            "            background-color: #f4f7f6;"
            "            display: flex;"
            "            justify-content: center;"
            "            align-items: center;"
            "            height: 100vh;"
            "            margin: 0;"
            "        }"
            "        .container {"
            "            background-color: #ffffff;"
            "            padding: 40px;"
            "            border-radius: 8px;"
            "            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);"
            "            width: 300px;"
            "        }"
            "        h1 {"
            "            text-align: center;"
            "            color: #333333;"
            "            margin-bottom: 24px;"
            "        }"
            "        label {"
            "            display: block;"
            "            margin-bottom: 8px;"
            "            color: #555555;"
            "            font-size: 14px;"
            "        }"
            "        input[type='text'],"
            "        input[type='password'] {"
            "            width: 100%;"
            "            padding: 10px;"
            "            margin-bottom: 20px;"
            "            border: 1px solid #ccc;"
            "            border-radius: 4px;"
            "            box-sizing: border-box;"
            "        }"
            "        input[type='submit'] {"
            "            width: 100%;"
            "            padding: 10px;"
            "            background-color: #28a745;"
            "            border: none;"
            "            border-radius: 4px;"
            "            color: white;"
            "            font-size: 16px;"
            "            cursor: pointer;"
            "        }"
            "        input[type='submit']:hover {"
            "            background-color: #218838;"
            "        }"
            "        .footer {"
            "            text-align: center;"
            "            margin-top: 20px;"
            "            font-size: 12px;"
            "            color: #aaa;"
            "        }"
            "    </style>"
            "</head>"
            "<body>"
            "    <div class='container'>"
            "        <h1>Admin Login</h1>"
            "        <form action='/login' method='post'>"
            "            <label for='username'>Username</label>"
            "            <input type='text' id='username' name='username' required>"
            "            <label for='password'>Password</label>"
            "            <input type='password' id='password' name='password' required>"
            "            <input type='submit' value='Login'>"
            "        </form>"
            "        <div class='footer'>"
            "            &copy; 2025"
            "        </div>"
            "    </div>"
            "</body>"
            "</html>"
        )

        conn_client.sendall(response.encode('utf-8'))
    except Exception as e:
        print(f"Error handling HTTP client {src_ip}: {e}")
    finally:
        conn_client.close()

def start_http_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"HTTP Honeypot listening on {HOST}:{PORT}")
    try:
        while True:
            conn_client, addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn_client, addr))
            client_thread.start()
    except KeyboardInterrupt:
        print("Shutting down HTTP Honeypot.")
    finally:
        server.close()
        conn.close()

if __name__ == "__main__":
    start_http_honeypot()
