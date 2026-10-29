import warnings

import pytest
from sklearn.exceptions import InconsistentVersionWarning

from incident_response import IncidentResponseGenerator
from validation import ValidationError, validate_report


def test_hunting_hashes_use_matching_columns_and_names(sample_analysis_result):
    sample_analysis_result.iocs.file_hashes = [{"md5": "a" * 32}, {"sha256": "b" * 64}]
    sample_analysis_result.iocs.filenames = [r"C:\Temp\sample.exe"]
    hunts = IncidentResponseGenerator()._build_scope_hunting(sample_analysis_result)
    query = next(h["query"] for h in hunts if "DeviceFileEvents" in h["query"])
    assert 'MD5 in ("' + 'a' * 32 + '")' in query
    assert 'SHA256 in ("' + 'b' * 64 + '")' in query
    assert 'FileName in ("sample.exe")' in query


def test_incompatible_ml_model_is_not_used(monkeypatch, sample_analysis_result):
    from ml_engine import MLThreatPredictor
    monkeypatch.setattr("ml_engine.os.path.exists", lambda _: True)
    def incompatible(_):
        warnings.warn(InconsistentVersionWarning(estimator_name="test", current_sklearn_version="2", original_sklearn_version="1"))
    monkeypatch.setattr("ml_engine.joblib.load", incompatible)
    predictor = MLThreatPredictor("test.pkl")
    assert not predictor.is_loaded and predictor.model is None
    assert predictor.predict(sample_analysis_result)["status"] == "disabled"


@pytest.mark.parametrize("content", [{"dropped": [{"hashes": []}]}, {"processes": [{"scores": []}]},
                                    {"processes": [{"scores": {"verdict": []}}]}, {"registry": [{"key": {}}]}])
def test_malformed_nested_report_rejected(content):
    with pytest.raises(ValidationError):
        validate_report({"data": {"content": content}}, {})
