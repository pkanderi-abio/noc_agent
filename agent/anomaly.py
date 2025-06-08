import os
import joblib
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self, model_path=None, contamination=0.01):
        self.model_path = model_path or os.getenv('NOC_ANOMALY_MODEL')
        if self.model_path and os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        else:
            self.model = IsolationForest(contamination=contamination)

    def train(self, X, save_path=None):
        """
        Train the isolation forest on feature matrix X and save model.
        """
        self.model.fit(X)
        path = save_path or self.model_path or 'models/anomaly_model.pkl'
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.model, path)
        return path

    def detect(self, features):
        """
        Return True if anomalous (prediction -1), False otherwise.
        """
        if not hasattr(self.model, 'predict'):
            raise RuntimeError("Model not trained or loaded")
        pred = self.model.predict([features])[0]
        return pred == -1