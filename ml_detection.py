# ml_detection.py

import pandas as pd
import sqlite3
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# Configuration
DATABASE = 'honeypot_logs.db'
MODEL_FILE = 'ml_model.pkl'

def prepare_data():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    ssh_logs = pd.read_sql_query("SELECT * FROM ssh_logs", conn)

    ssh_logs['is_attack'] = ssh_logs['attempted_password'].apply(lambda x: 1 if x.lower() != 'password' else 0)
    ssh_logs['timestamp'] = pd.to_datetime(ssh_logs['timestamp'])
    ssh_logs['hour'] = ssh_logs['timestamp'].dt.hour

    ssh_logs['src_ip'] = ssh_logs['src_ip'].astype('category').cat.codes

    features = ssh_logs[['src_ip', 'hour']]
    labels = ssh_logs['is_attack']

    conn.close()
    return features, labels

def train_model():
    features, labels = prepare_data()
    X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.3, random_state=42)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))

    joblib.dump(clf, MODEL_FILE)
    print(f"Model saved to {MODEL_FILE}")

def load_model():
    return joblib.load(MODEL_FILE)

def detect_anomalies(new_data):
    model = load_model()
    predictions = model.predict(new_data)
    return predictions

if __name__ == "__main__":
    train_model()
