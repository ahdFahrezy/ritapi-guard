import logging
import joblib
import pandas as pd
from django.core.management.base import BaseCommand
from ai_behaviour.models import BehaviourLogs
from sklearn.ensemble import IsolationForest
from django.conf import settings
from pathlib import Path

logger = logging.getLogger("ai_behaviour")

MODEL_PATH = Path(settings.BASE_DIR) / "models" / "iforest.pkl"

class Command(BaseCommand):
    help = "Train IsolationForest model for behaviour anomaly detection"

    def handle(self, *args, **kwargs):
        logger.info("=== Train IsolationForest started ===")

        try:
            logs = BehaviourLogs.objects.all().order_by("-timestamp")[:5000]
            logger.info("Fetched %s logs for training", len(logs))

            if len(logs) < 50:
                logger.warning("Not enough data for training (found=%s, need>=50)", len(logs))
                return

            df = pd.DataFrame(list(logs.values("payload_size", "response_time_ms", "status_code")))
            X = df[["payload_size", "response_time_ms", "status_code"]]

            logger.info("Preparing dataset with shape %s", X.shape)

            clf = IsolationForest(contamination=0.1, random_state=42)
            clf.fit(X)

            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(clf, MODEL_PATH)

            logger.info("Training completed successfully. Model saved at %s", MODEL_PATH)
            logger.info("=== Train IsolationForest finished ===")

        except Exception as e:
            logger.exception("Training failed due to: %s", str(e))
