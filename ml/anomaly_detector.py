import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import pickle, os

MODEL_PATH = 'anomaly_model.pkl'

class AnomalyDetector:
    def __init__(self, contamination=0.05):
        self.model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        self.encoder = LabelEncoder()
        self.trained = False

    def train(self, events_list):
        if len(events_list) < 20:
            return False
        df = pd.DataFrame(events_list)
        features = self._extract_features(df)
        self.model.fit(features)
        self.trained = True
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump({'model': self.model, 'encoder': self.encoder}, f)
        return True

    def load(self):
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, 'rb') as f:
                data = pickle.load(f)
                self.model = data['model']
                self.encoder = data['encoder']
                self.trained = True
            return True
        return False

    def predict(self, event_dict):
        if not self.trained:
            return False, 0.0
        df = pd.DataFrame([event_dict])
        features = self._extract_features(df)
        score = self.model.decision_function(features)[0]
        prediction = self.model.predict(features)[0]
        return prediction == -1, float(score)

    def _extract_features(self, df):
        df = df.copy()
        df['hour'] = pd.to_datetime(df.get('timestamp', pd.Timestamp.now()), errors='coerce').dt.hour.fillna(0)
        types = df.get('event_type', pd.Series(['UNKNOWN'] * len(df))).fillna('UNKNOWN')
        try:
            df['event_type_enc'] = self.encoder.fit_transform(types)
        except Exception:
            df['event_type_enc'] = 0
        outcomes = df.get('outcome', pd.Series([''] * len(df))).fillna('')
        df['is_failure'] = (outcomes == 'FAILURE').astype(int)
        df['severity'] = pd.to_numeric(df.get('severity', 0), errors='coerce').fillna(0)
        return df[['hour', 'event_type_enc', 'is_failure', 'severity']].fillna(0)

detector = AnomalyDetector()
detector.load()
