
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


class IoTAnomalyDetector:

    def __init__(self):

        # AI training model
        self.model = Pipeline([
            ("scaler", StandardScaler()),

            ("detector", IsolationForest(
                n_estimators=150,
                contamination=0.05,
                random_state=42
            ))
        ])

        self.is_trained = False

    def train_model(self):

        # Generate normal IoT sensor behavior
        np.random.seed(42)

        normal_data = np.column_stack([

            np.random.normal(27, 2, 1000),

            np.random.normal(50, 8, 1000),

            np.random.normal(50, 15, 1000),

            np.random.poisson(0.2, 1000)

        ])

        # Train AI model
        self.model.fit(normal_data)

        self.is_trained = True

        print("AI model trained successfully!")

    def detect_anomaly(self, temperature, humidity,
                       network_rate, failed_logins):

        if not self.is_trained:
            self.train_model()

        # Prepare IoT device data
        input_data = np.array([[
            temperature,
            humidity,
            network_rate,
            failed_logins
        ]])

        # AI prediction
        prediction = self.model.predict(input_data)[0]

        # Anomaly score
        raw_score = self.model.decision_function(input_data)[0]

        anomaly_score = round(
            max(0, min(100, (0.15 - raw_score) * 250)),
            2
        )

        if prediction == -1:
            status = "ANOMALY DETECTED"
            risk = "HIGH"
        else:
            status = "NORMAL"
            risk = "LOW"

        return {
            "status": status,
            "risk": risk,
            "anomaly_score": anomaly_score,
            "temperature": temperature,
            "humidity": humidity,
            "network_rate": network_rate,
            "failed_logins": failed_logins
        }


# Test the AI engine
if __name__ == "__main__":

    detector = IoTAnomalyDetector()

    detector.train_model()

    print("\n----- NORMAL DEVICE TEST -----")

    normal_result = detector.detect_anomaly(
        temperature=27,
        humidity=50,
        network_rate=45,
        failed_logins=0
    )

    print(normal_result)

    print("\n----- SUSPICIOUS DEVICE TEST -----")

    suspicious_result = detector.detect_anomaly(
        temperature=90,
        humidity=95,
        network_rate=950,
        failed_logins=20
    )

    print(suspicious_result)
