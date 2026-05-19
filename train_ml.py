from __future__ import annotations

import argparse
import json
import os
import random
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from analyzer import MalwareAnalyzer, MalwareAnalysisResult


FEATURE_NAMES = [
    "num_ips",
    "num_domains",
    "num_http",
    "num_processes",
    "num_injected",
    "num_dropped",
    "num_registry",
    "has_persistence",
    "has_evasion",
    "has_c2",
    "has_impact",
]

LABELS = {
    0: "Clean",
    1: "Suspicious",
    2: "Malicious",
}


def features_from_result(result: MalwareAnalysisResult) -> list[int]:
    tactics = [m.get("tactic", "") for m in result.threat_info.mitre_techniques]
    return [
        len(result.network.ip_addresses),
        len(result.network.domains),
        len(result.network.http_requests),
        len(result.processes.processes),
        len(result.processes.injected_processes),
        len(result.processes.dropped_files),
        len(result.processes.registry_keys),
        1 if any("Persistence" in t for t in tactics) else 0,
        1 if any("Defense Evasion" in t for t in tactics) else 0,
        1 if any("Command and Control" in t for t in tactics) else 0,
        1 if any("Impact" in t for t in tactics) else 0,
    ]


def features_from_payload(payload: dict[str, Any]) -> list[int]:
    threat = payload.get("threat", {}) or {}
    network = payload.get("network", {}) or {}
    processes = payload.get("processes", {}) or {}
    tactics = [m.get("tactic", "") for m in threat.get("mitre", []) or []]
    return [
        len(network.get("ips", []) or []),
        len(network.get("domains", []) or []),
        len(network.get("http", []) or []),
        len(processes.get("list", []) or []),
        len(processes.get("injected", []) or []),
        len(processes.get("dropped", []) or []),
        len(processes.get("registry", []) or []),
        1 if any("Persistence" in t for t in tactics) else 0,
        1 if any("Defense Evasion" in t for t in tactics) else 0,
        1 if any("Command and Control" in t for t in tactics) else 0,
        1 if any("Impact" in t for t in tactics) else 0,
    ]


def label_from_threat_level(level: int) -> int:
    if level <= 0:
        return 0
    if level == 1:
        return 1
    return 2


def load_seed_dataset(path: Path) -> tuple[list[list[int]], list[int], list[str]]:
    if not path.exists():
        return [], [], []

    raw = json.loads(path.read_text(encoding="utf-8"))
    rows = raw.get("samples", raw if isinstance(raw, list) else [])
    X: list[list[int]] = []
    y: list[int] = []
    sources: list[str] = []

    for row in rows:
        features = row.get("features", {})
        if isinstance(features, dict):
            vector = [int(features.get(name, 0)) for name in FEATURE_NAMES]
        else:
            vector = [int(v) for v in features]
        if len(vector) != len(FEATURE_NAMES):
            continue
        X.append(vector)
        y.append(int(row.get("label", 2)))
        sources.append(row.get("source", "seed"))
    return X, y, sources


def load_demo_dataset() -> tuple[list[list[int]], list[int], list[str]]:
    analyzer = MalwareAnalyzer()
    demos = []
    try:
        from demo_data import DEMO_IOC, DEMO_REPORT
        demos.append(("demo:emotet", DEMO_REPORT, DEMO_IOC))
    except Exception:
        pass
    try:
        from demo_data_wannacry import DEMO_WANNACRY_IOC, DEMO_WANNACRY_REPORT
        demos.append(("demo:wannacry", DEMO_WANNACRY_REPORT, DEMO_WANNACRY_IOC))
    except Exception:
        pass
    try:
        from demo_data_redline import DEMO_REDLINE_IOC, DEMO_REDLINE_REPORT
        demos.append(("demo:redline", DEMO_REDLINE_REPORT, DEMO_REDLINE_IOC))
    except Exception:
        pass

    X: list[list[int]] = []
    y: list[int] = []
    sources: list[str] = []
    for source, report, ioc in demos:
        result = analyzer.parse_report(report, ioc)
        X.append(features_from_result(result))
        y.append(label_from_threat_level(result.threat_info.threat_level))
        sources.append(source)
    return X, y, sources


def load_history_dataset(path: Path) -> tuple[list[list[int]], list[int], list[str]]:
    if not path.exists():
        return [], [], []
    try:
        items = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return [], [], []

    X: list[list[int]] = []
    y: list[int] = []
    sources: list[str] = []
    for item in items if isinstance(items, list) else []:
        payload = item.get("payload")
        if not isinstance(payload, dict):
            continue
        X.append(features_from_payload(payload))
        y.append(label_from_threat_level(int(item.get("threat_level", 0))))
        sources.append(f"history:{item.get('source', 'local')}")
    return X, y, sources


def generate_synthetic_data(num_samples: int = 0, seed: int = 42) -> tuple[list[list[int]], list[int], list[str]]:
    if num_samples <= 0:
        return [], [], []
    rng = random.Random(seed)
    X: list[list[int]] = []
    y: list[int] = []
    sources: list[str] = []

    for _ in range(num_samples):
        label = rng.choice([0, 1, 2])
        if label == 0:
            vector = [
                rng.randint(0, 2),
                rng.randint(0, 2),
                rng.randint(0, 2),
                rng.randint(1, 10),
                0,
                rng.randint(0, 2),
                rng.randint(0, 5),
                0,
                0,
                0,
                0,
            ]
        elif label == 1:
            vector = [
                rng.randint(1, 5),
                rng.randint(1, 4),
                rng.randint(1, 5),
                rng.randint(5, 15),
                rng.randint(0, 1),
                rng.randint(1, 5),
                rng.randint(5, 15),
                rng.choice([0, 1]),
                0,
                rng.choice([0, 1]),
                0,
            ]
        else:
            vector = [
                rng.randint(2, 10),
                rng.randint(2, 8),
                rng.randint(1, 8),
                rng.randint(8, 25),
                rng.randint(1, 5),
                rng.randint(3, 10),
                rng.randint(10, 30),
                1,
                1,
                1,
                rng.choice([0, 1]),
            ]
        X.append(vector)
        y.append(label)
        sources.append("synthetic")
    return X, y, sources


def combine_datasets(parts: list[tuple[list[list[int]], list[int], list[str]]]) -> tuple[np.ndarray, np.ndarray, list[str]]:
    X: list[list[int]] = []
    y: list[int] = []
    sources: list[str] = []
    for part_X, part_y, part_sources in parts:
        X.extend(part_X)
        y.extend(part_y)
        sources.extend(part_sources)
    return np.array(X, dtype=int), np.array(y, dtype=int), sources


def train(args: argparse.Namespace) -> None:
    seed_path = Path(args.dataset)
    history_path = Path(args.history)

    parts = [
        load_seed_dataset(seed_path),
        load_demo_dataset(),
        load_history_dataset(history_path),
        generate_synthetic_data(args.synthetic, args.random_state),
    ]
    X, y, sources = combine_datasets(parts)
    if len(X) < 9 or len(set(y.tolist())) < 2:
        raise SystemExit("Khong du du lieu de train. Hay them data/ml_training_seed.json hoac bat --synthetic.")

    counts = {LABELS[i]: int((y == i).sum()) for i in sorted(set(y.tolist()))}
    print(f"[*] Dataset: {len(X)} mau | phan bo nhan: {counts}")
    print(f"[*] Nguon du lieu: {sorted(set(sources))}")

    stratify = y if min((y == label).sum() for label in set(y.tolist())) >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=stratify,
    )

    model = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        random_state=args.random_state,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("[*] Danh gia tren tap test:")
    print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%\n")
    labels_present = sorted(set(y_test.tolist()) | set(y_pred.tolist()))
    print(
        classification_report(
            y_test,
            y_pred,
            labels=labels_present,
            target_names=[LABELS[i] for i in labels_present],
            zero_division=0,
        )
    )

    model_dir = Path(args.output_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "rf_threat_model.pkl"
    joblib.dump(model, model_path)

    metadata = {
        "feature_names": FEATURE_NAMES,
        "labels": LABELS,
        "sample_count": int(len(X)),
        "label_counts": counts,
        "sources": sorted(set(sources)),
        "note": "Bootstrap ML dataset: public/OSINT-derived seed + local Any.Run/demo history. Do not treat as a benchmark-grade detector.",
    }
    (model_dir / "rf_threat_model.meta.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[+] Da luu model: {model_path}")
    print(f"[+] Da luu metadata: {model_dir / 'rf_threat_model.meta.json'}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train ML threat classifier from seed, demo, history and optional synthetic data.")
    parser.add_argument("--dataset", default="data/ml_training_seed.json", help="JSON dataset seed da chuan hoa feature.")
    parser.add_argument("--history", default="reports/analysis_history.json", help="Lich su phan tich local cua app.")
    parser.add_argument("--output-dir", default="models", help="Thu muc luu model.")
    parser.add_argument("--synthetic", type=int, default=0, help="So mau synthetic bo sung neu can. Mac dinh 0.")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


if __name__ == "__main__":
    train(parse_args())
