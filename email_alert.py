# email_alert.py

import smtplib
from email.mime.text import MIMEText
import sqlite3
import datetime
import pandas as pd
import joblib

# Configuration
SMTP_SERVER = 'smtp.example.com'  # Replace with your SMTP server
SMTP_PORT = 587
SMTP_USER = 'your_email@example.com'
SMTP_PASSWORD = 'your_password'
TO_EMAIL = 'admin@example.com'

MODEL_FILE = 'ml_model.pkl'

def send_email(subject, message):
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = TO_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"Email sent to {TO_EMAIL}")
    except Exception as e:
        print(f"Failed to send email: {e}")

def load_model():
    return joblib.load(MODEL_FILE)

def check_anomalies():
    conn = sqlite3.connect('honeypot_logs.db')
    c = conn.cursor()
    # Load recent SSH logs (last 1 hour)
    since_time = (datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat()
    c.execute('''
        SELECT src_ip, hour
        FROM ssh_logs
        WHERE timestamp >= ?
    ''', (since_time,))
    rows = c.fetchall()
    conn.close()

    if not rows:
        return []

    df = pd.DataFrame(rows, columns=['src_ip', 'hour'])
    # Encode src_ip as done during training
    # Note: In a real scenario, ensure consistent encoding
    df['src_ip'] = df['src_ip'].astype('category').cat.codes

    model = load_model()
    predictions = model.predict(df)
    anomalies = df[predictions == 1]
    return anomalies['src_ip'].unique()

def main():
    anomalies = check_anomalies()
    if len(anomalies) > 0:
        message = "Anomalous SSH login attempts detected from the following IPs:\n\n"
        for ip_code in anomalies:
            # Reverse mapping of src_ip codes to actual IPs would be needed
            message += f"Source IP Code: {ip_code}\n"
        send_email("Honeypot Alert: Anomalous SSH Attempts Detected", message)

if __name__ == "__main__":
    main()
