import os
import joblib
import numpy as np

class MLThreatPredictor:
    """
    Tích hợp Machine Learning để phân tích mức độ nguy hiểm của mã độc.
    Sử dụng Random Forest Classifier (được huấn luyện trước).
    """
    def __init__(self, model_path="models/rf_threat_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.is_loaded = False
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.is_loaded = True
            except Exception as e:
                print(f"[ML] Không thể tải mô hình: {e}")
        else:
            print("[ML] Chưa có mô hình. Cần chạy train_ml.py trước.")

    def extract_features(self, analysis_result):
        """
        Trích xuất đặc trưng (Features) từ MalwareAnalysisResult.
        Trả về một mảng numpy 1D chứa các chỉ số số học.
        """
        # 1. Network Features
        num_ips = len(analysis_result.network.ip_addresses)
        num_domains = len(analysis_result.network.domains)
        num_http = len(analysis_result.network.http_requests)
        
        # 2. Process & File Features
        num_processes = len(analysis_result.processes.processes)
        num_injected = len(analysis_result.processes.injected_processes)
        num_dropped = len(analysis_result.processes.dropped_files)
        num_registry = len(analysis_result.processes.registry_keys)
        
        # 3. MITRE Tactic Features (Kiểm tra xem có tactic cụ thể không)
        mitre_tactics = [m.get("tactic", "") for m in analysis_result.threat_info.mitre_techniques]
        has_persistence = 1 if any("Persistence" in t for t in mitre_tactics) else 0
        has_evasion = 1 if any("Defense Evasion" in t for t in mitre_tactics) else 0
        has_c2 = 1 if any("Command and Control" in t for t in mitre_tactics) else 0
        has_impact = 1 if any("Impact" in t for t in mitre_tactics) else 0

        # Vector đặc trưng (11 features)
        features = [
            num_ips,
            num_domains,
            num_http,
            num_processes,
            num_injected,
            num_dropped,
            num_registry,
            has_persistence,
            has_evasion,
            has_c2,
            has_impact
        ]
        return np.array(features).reshape(1, -1)

    def predict(self, analysis_result):
        """
        Dự đoán xác suất và nhãn: 0 (Clean), 1 (Suspicious), 2 (Malicious)
        """
        if not self.is_loaded or self.model is None:
            return {
                "status": "disabled",
                "message": "Chưa có model ML"
            }
            
        try:
            X = self.extract_features(analysis_result)
            pred = self.model.predict(X)[0]        # Nhãn dự đoán
            probs = self.model.predict_proba(X)[0] # Xác suất cho từng class
            
            confidence = float(round(float(max(probs)) * 100, 2))
            
            labels = {0: "Clean", 1: "Suspicious", 2: "Malicious"}
            pred_label = labels.get(pred, "Unknown")
            
            return {
                "status": "success",
                "prediction": pred_label,
                "confidence": confidence,
                "probabilities": {
                    "Clean": float(round(float(probs[0]) * 100, 2)) if len(probs) > 0 else 0,
                    "Suspicious": float(round(float(probs[1]) * 100, 2)) if len(probs) > 1 else 0,
                    "Malicious": float(round(float(probs[2]) * 100, 2)) if len(probs) > 2 else 0,
                }
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
