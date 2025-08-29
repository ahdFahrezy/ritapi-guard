import pandas as pd
from django.utils import timezone
from sklearn.ensemble import IsolationForest
from .models import BehaviourLogs, BehaviourAnomaly
import joblib
import os

MODEL_PATH = "models/iforest.pkl"

class AiProfilerService:
    model = None

    @staticmethod
    def log_request(endpoint, ip, method, payload_size, user_agent, status_code, response_time_ms):
        """
        Simpan request log ke BehaviourLogs + deteksi anomali
        """
        log = BehaviourLogs.objects.create(
            endpoint=endpoint,
            ip_address=ip,
            method=method,
            payload_size=payload_size,
            user_agent=user_agent,
            status_code=status_code,
            response_time_ms=response_time_ms,
        )

        # cek anomali
        AiProfilerService.detect_anomaly(log)

        return log
    
    @staticmethod
    def load_model():
        if AiProfilerService.model is None and os.path.exists(MODEL_PATH):
            AiProfilerService.model = joblib.load(MODEL_PATH)

    @staticmethod
    def detect_anomaly(log: BehaviourLogs):
        """
        Deteksi anomali:
        - Rule-Based sederhana
        - IsolationForest ML
        """
        anomalies = []

        # === RULE-BASED ANOMALY ===
        if log.payload_size > 10_000:  # >10KB
            anomalies.append(("Large Payload", 70))

        if log.response_time_ms > 2000:  # >2 detik
            anomalies.append(("Slow Response", 50))

        if log.payload_size % 13 == 0:  # pola dummy
            anomalies.append(("Suspicious Payload Pattern", 60))

        for anomaly_type, score in anomalies:
            BehaviourAnomaly.objects.create(
                log=log,
                ip_address=log.ip_address,
                anomaly_type=anomaly_type,
                risk_score=score,
                detected_at=timezone.now(),
                detected_by="rule",
            )

        # === ML ANOMALY (IsolationForest Pre-trained) ===
        if not os.path.exists(MODEL_PATH):
            return None  # model belum ada

        clf = joblib.load(MODEL_PATH)

        df = pd.DataFrame([{
            "payload_size": log.payload_size,
            "response_time_ms": log.response_time_ms,
            "status_code": log.status_code
        }])

        pred = clf.predict(df)[0]
        if pred == -1:
            BehaviourAnomaly.objects.create(
                log=log,
                ip_address=log.ip_address,
                anomaly_type="IsolationForest Detected Anomaly",
                risk_score=80,
                detected_by="ml",
            )
            return True
        return False

