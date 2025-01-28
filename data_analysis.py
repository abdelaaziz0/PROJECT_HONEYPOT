# data_analysis.py

import pandas as pd
import sqlite3
import matplotlib.pyplot as plt

conn = sqlite3.connect('honeypot_logs.db')
ssh_logs = pd.read_sql_query("SELECT * FROM ssh_logs", conn)
http_logs = pd.read_sql_query("SELECT * FROM http_logs", conn)
packet_logs = pd.read_sql_query("SELECT * FROM packet_logs", conn)
conn.close()
ssh_logs['timestamp'] = pd.to_datetime(ssh_logs['timestamp'])
http_logs['timestamp'] = pd.to_datetime(http_logs['timestamp'])
packet_logs['timestamp'] = pd.to_datetime(packet_logs['timestamp'])

top_ssh_ips = ssh_logs['src_ip'].value_counts().head(10)
top_ssh_ips.plot(kind='bar', title='Top 10 Source IPs for SSH Attempts')
plt.xlabel('Source IP')
plt.ylabel('Number of Attempts')
plt.savefig('top_ssh_ips.png')
plt.show()

top_http_ips = http_logs['src_ip'].value_counts().head(10)
top_http_ips.plot(kind='bar', title='Top 10 Source IPs for HTTP Requests')
plt.xlabel('Source IP')
plt.ylabel('Number of Requests')
plt.savefig('top_http_ips.png')
plt.show()

http_logs['request_type'] = http_logs['request'].apply(lambda x: x.split(' ')[0])
request_distribution = http_logs['request_type'].value_counts()
request_distribution.plot(kind='pie', autopct='%1.1f%%', title='Distribution of HTTP Request Types')
plt.ylabel('')
plt.savefig('http_request_distribution.png')
plt.show()

protocol_counts = packet_logs['protocol'].value_counts()
protocol_counts.plot(kind='pie', autopct='%1.1f%%', title='Packet Protocol Distribution')
plt.ylabel('')
plt.savefig('protocol_distribution.png')
plt.show()

ssh_logs.set_index('timestamp', inplace=True)
ssh_time_series = ssh_logs.resample('D').count()['id']
ssh_time_series.plot(kind='line', title='Daily SSH Attempts')
plt.xlabel('Date')
plt.ylabel('Number of Attempts')
plt.savefig('ssh_time_series.png')
plt.show()

http_logs.set_index('timestamp', inplace=True)
http_time_series = http_logs.resample('D').count()['id']
http_time_series.plot(kind='line', title='Daily HTTP Requests')
plt.xlabel('Date')
plt.ylabel('Number of Requests')
plt.savefig('http_time_series.png')
plt.show()
