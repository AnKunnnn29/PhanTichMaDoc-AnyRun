from __future__ import annotations

import numpy as np
import pytest

from ml_engine import MLThreatPredictor

pytestmark = pytest.mark.unit


class TestMLInitialization:
    def test_initialization_without_model_sets_is_loaded_false(self, tmp_path):
        predictor = MLThreatPredictor(str(tmp_path / "missing.pkl"))

        assert predictor.is_loaded is False
        assert predictor.model is None

    def test_predict_without_loaded_model_returns_disabled(self, tmp_path, sample_analysis_result):
        predictor = MLThreatPredictor(str(tmp_path / "missing.pkl"))

        result = predictor.predict(sample_analysis_result)

        assert result["status"] == "disabled"
        assert "model ML" in result["message"]

    def test_initialization_loads_existing_model(self, monkeypatch):
        class MockModel:
            pass

        monkeypatch.setattr("ml_engine.os.path.exists", lambda path: True)
        monkeypatch.setattr("ml_engine.joblib.load", lambda path: MockModel())

        predictor = MLThreatPredictor("model.pkl")

        assert predictor.is_loaded is True
        assert isinstance(predictor.model, MockModel)

    def test_failed_model_load_keeps_predictor_disabled(self, monkeypatch):
        monkeypatch.setattr("ml_engine.os.path.exists", lambda path: True)
        monkeypatch.setattr("ml_engine.joblib.load", lambda path: (_ for _ in ()).throw(RuntimeError("bad model")))

        predictor = MLThreatPredictor("model.pkl")

        assert predictor.is_loaded is False


class TestFeatureExtraction:
    def test_extract_features_has_expected_shape(self, tmp_path, sample_analysis_result):
        predictor = MLThreatPredictor(str(tmp_path / "missing.pkl"))

        features = predictor.extract_features(sample_analysis_result)

        assert features.shape == (1, 11)

    def test_extract_features_counts_network_and_process_features(self, tmp_path, sample_analysis_result):
        predictor = MLThreatPredictor(str(tmp_path / "missing.pkl"))

        features = predictor.extract_features(sample_analysis_result)[0]

        assert features[0] == 2
        assert features[1] == 2
        assert features[2] == 1
        assert features[3] == 2
        assert features[4] == 1
        assert features[5] == 1
        assert features[6] == 1

    def test_mitre_tactic_features_are_binary(self, tmp_path, sample_analysis_result):
        predictor = MLThreatPredictor(str(tmp_path / "missing.pkl"))

        features = predictor.extract_features(sample_analysis_result)[0]

        for value in features[7:]:
            assert value in {0, 1}
        assert features[7] == 1
        assert features[9] == 1


class TestPrediction:
    def test_predict_returns_valid_label_confidence_and_probabilities(self, monkeypatch, sample_analysis_result):
        class MockModel:
            def predict(self, X):
                return np.array([2])

            def predict_proba(self, X):
                return np.array([[0.1, 0.2, 0.7]])

        monkeypatch.setattr("ml_engine.os.path.exists", lambda path: True)
        monkeypatch.setattr("ml_engine.joblib.load", lambda path: MockModel())
        predictor = MLThreatPredictor("model.pkl")

        result = predictor.predict(sample_analysis_result)

        assert result["status"] == "success"
        assert result["prediction"] in ["Clean", "Suspicious", "Malicious"]
        assert 0 <= result["confidence"] <= 100
        assert result["probabilities"]["Malicious"] == 70.0

    def test_predict_unknown_label_maps_to_unknown(self, monkeypatch, sample_analysis_result):
        class MockModel:
            def predict(self, X):
                return np.array([99])

            def predict_proba(self, X):
                return np.array([[1.0]])

        monkeypatch.setattr("ml_engine.os.path.exists", lambda path: True)
        monkeypatch.setattr("ml_engine.joblib.load", lambda path: MockModel())

        result = MLThreatPredictor("model.pkl").predict(sample_analysis_result)

        assert result["prediction"] == "Unknown"
        assert result["probabilities"]["Clean"] == 100.0
        assert result["probabilities"]["Suspicious"] == 0

    def test_predict_returns_error_for_unexpected_input(self, monkeypatch):
        class MockModel:
            def predict(self, X):
                return np.array([0])

            def predict_proba(self, X):
                return np.array([[1.0, 0.0, 0.0]])

        monkeypatch.setattr("ml_engine.os.path.exists", lambda path: True)
        monkeypatch.setattr("ml_engine.joblib.load", lambda path: MockModel())

        result = MLThreatPredictor("model.pkl").predict(object())

        assert result["status"] == "error"
