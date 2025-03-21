import pandas as pd
import sqlite3
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from imblearn.over_sampling import SMOTE
import joblib
import os
from scipy.stats import randint, uniform

DATABASE = 'honeypot_logs.db'
MODEL_FILE = 'ml_model.pkl'
ENCODER_FILE = 'label_encoder.pkl'

def prepare_data():
    """
    Charge les données depuis la base de données SQLite et effectue le prétraitement initial.
    """
    conn = sqlite3.connect(DATABASE)
    ssh_logs = pd.read_sql_query("SELECT * FROM ssh_logs", conn)
    web_logs = pd.read_sql_query("SELECT * FROM web_logs", conn)

    conn.close()
    ssh_logs['timestamp'] = pd.to_datetime(ssh_logs['timestamp'])
    ssh_logs['hour'] = ssh_logs['timestamp'].dt.hour
    ssh_logs['day_of_week'] = ssh_logs['timestamp'].dt.dayofweek
    ssh_logs['src_ip'] = ssh_logs['src_ip'].astype('category').cat.codes
    web_logs['timestamp'] = pd.to_datetime(web_logs['timestamp'])
    web_logs['hour'] = web_logs['timestamp'].dt.hour
    web_logs['day_of_week'] = web_logs['timestamp'].dt.dayofweek
    web_logs['src_ip'] = web_logs['src_ip'].astype('category').cat.codes
    ssh_features = ssh_logs[['src_ip', 'hour', 'day_of_week', 'attempted_password', 'attack_type']]
    web_features = web_logs[['src_ip', 'hour', 'day_of_week', 'attempted_url', 'user_agent', 'attack_type']]

    ssh_features['source'] = 'ssh'
    web_features['source'] = 'web'
    all_logs = pd.concat([ssh_features, web_features], ignore_index=True)
    all_logs.fillna('unknown', inplace=True)

    label_encoder = LabelEncoder()
    all_logs['attack_type_encoded'] = label_encoder.fit_transform(all_logs['attack_type'])

    joblib.dump(label_encoder, ENCODER_FILE)
    print(f"Encodeur de labels sauvegardé dans {ENCODER_FILE}")

    features = all_logs[['src_ip', 'hour', 'day_of_week', 'attempted_password', 'attempted_url', 'user_agent', 'source']]
    labels = all_logs['attack_type_encoded']

    return features, labels, label_encoder

def encode_features(features):
    """
    Encode les caractéristiques catégorielles et textuelles.
    """
    categorical_cols = ['attempted_password', 'attempted_url', 'user_agent', 'source']

    for col in categorical_cols:
        freq_encoding = features[col].value_counts(normalize=True)
        features[f'{col}_freq'] = features[col].map(freq_encoding)
        features.drop(col, axis=1, inplace=True)
        print(f"Encodage de fréquence appliqué à la colonne {col}")

    return features

def handle_imbalance(features, labels):
    """
    Applique SMOTE pour équilibrer les classes minoritaires.
    """
    smote = SMOTE(random_state=42)
    features_resampled, labels_resampled = smote.fit_resample(features, labels)
    print("SMOTE a été appliqué pour équilibrer les classes.")
    return features_resampled, labels_resampled

def train_model():
    """
    Entraîne le modèle de machine learning avec les données préparées.
    """
    features, labels, label_encoder = prepare_data()
    features_encoded = encode_features(features)
    features_balanced, labels_balanced = handle_imbalance(features_encoded, labels)
    X_train, X_test, y_train, y_test = train_test_split(
        features_balanced,
        labels_balanced,
        test_size=0.3,
        random_state=42,
        stratify=labels_balanced
    )
    print("Données divisées en ensembles d'entraînement et de test.")
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', RandomForestClassifier(random_state=42))
    ])
    param_distributions = {
        'clf__n_estimators': randint(50, 201),          
        'clf__max_depth': [None, 10, 20],
        'clf__min_samples_split': randint(2, 6),       
        'clf__min_samples_leaf': randint(1, 3),      
        'clf__bootstrap': [True, False]
    }
    random_search = RandomizedSearchCV(
        estimator=pipeline,
        param_distributions=param_distributions,
        n_iter=30,              
        cv=3,                   
        n_jobs=2,                
        verbose=2,
        scoring='f1_macro',
        random_state=42
    )
    print("Début de l'entraînement du modèle avec RandomizedSearchCV...")
    try:
        random_search.fit(X_train, y_train)
    except Exception as e:
        print(f"Erreur lors de l'entraînement du modèle : {e}")
        exit(1)
    

    print("Meilleurs paramètres trouvés :", random_search.best_params_)
    best_pipeline = random_search.best_estimator_

    y_pred = best_pipeline.predict(X_test)

    print("Rapport de classification :\n", classification_report(y_test, y_pred, target_names=label_encoder.classes_))
    print("Matrice de confusion :\n", confusion_matrix(y_test, y_pred))
    joblib.dump(best_pipeline, MODEL_FILE)
    print(f"Modèle sauvegardé dans {MODEL_FILE}")

def main():
    """
    Fonction principale pour orchestrer l'entraînement du modèle.
    """
    train_model()

if __name__ == "__main__":
    main()
