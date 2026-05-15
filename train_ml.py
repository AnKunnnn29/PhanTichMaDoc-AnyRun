import os
import random
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

def generate_synthetic_data(num_samples=2000):
    """
    Sinh dữ liệu giả lập để huấn luyện mô hình.
    Trong thực tế, bạn sẽ lấy dữ liệu này từ file JSON của hàng ngàn mẫu Any.Run.
    """
    X = []
    y = [] # 0: Clean, 1: Suspicious, 2: Malicious

    for _ in range(num_samples):
        label = random.choice([0, 1, 2])
        
        if label == 0: # Clean software
            num_ips = random.randint(0, 2)
            num_domains = random.randint(0, 2)
            num_http = random.randint(0, 2)
            num_processes = random.randint(1, 10)
            num_injected = 0
            num_dropped = random.randint(0, 2)
            num_registry = random.randint(0, 5)
            has_persistence = 0
            has_evasion = 0
            has_c2 = 0
            has_impact = 0
            
        elif label == 1: # Suspicious (Adware, PUP)
            num_ips = random.randint(1, 5)
            num_domains = random.randint(1, 4)
            num_http = random.randint(1, 5)
            num_processes = random.randint(5, 15)
            num_injected = random.randint(0, 1)
            num_dropped = random.randint(1, 5)
            num_registry = random.randint(5, 15)
            has_persistence = random.choice([0, 1])
            has_evasion = 0
            has_c2 = random.choice([0, 1])
            has_impact = 0
            
        else: # Malicious (Ransomware, Trojan, Stealer)
            num_ips = random.randint(2, 10)
            num_domains = random.randint(2, 8)
            num_http = random.randint(1, 8)
            num_processes = random.randint(8, 25)
            num_injected = random.randint(1, 5)
            num_dropped = random.randint(3, 10)
            num_registry = random.randint(10, 30)
            has_persistence = 1
            has_evasion = 1
            has_c2 = 1
            has_impact = random.choice([0, 1])

        features = [num_ips, num_domains, num_http, num_processes, num_injected, 
                    num_dropped, num_registry, has_persistence, has_evasion, has_c2, has_impact]
        
        X.append(features)
        y.append(label)

    return np.array(X), np.array(y)

def train():
    print("[*] Đang sinh bộ dữ liệu huấn luyện giả lập (2000 mẫu)...")
    X, y = generate_synthetic_data(2000)
    
    print("[*] Phân chia tập Train/Test...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("[*] Đang huấn luyện Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_train, y_train)
    
    print("[*] Đánh giá mô hình trên tập Test:")
    y_pred = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%\n")
    print(classification_report(y_test, y_pred, target_names=["Clean", "Suspicious", "Malicious"]))
    
    # Lưu mô hình
    os.makedirs("models", exist_ok=True)
    model_path = "models/rf_threat_model.pkl"
    joblib.dump(model, model_path)
    print(f"[+] Đã lưu mô hình thành công tại: {model_path}")

if __name__ == "__main__":
    train()
