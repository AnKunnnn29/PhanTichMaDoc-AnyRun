# Test Suite

This project uses pytest for unit tests, integration tests, coverage reporting, and lightweight performance benchmarks.

## Organization

- `tests/unit/`: isolated tests for core modules such as `analyzer.py`, `anyrun_client.py`, `incident_response.py`, `reporter.py`, and `ml_engine.py`.
- `tests/integration/`: Flask API, CLI, and full workflow tests.
- `tests/performance/`: `pytest-benchmark` checks for parser, playbook, and export speed.
- `tests/fixtures/`: static fixture placeholders. Shared fixtures in `tests/conftest.py` load the canonical demo data from the project modules.

## Run Tests

Install application and test dependencies:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Run everything:

```bash
pytest
```

Run only unit or integration tests:

```bash
pytest -m unit
pytest -m integration
```

Run a specific file or function:

```bash
pytest tests/unit/test_analyzer.py
pytest tests/unit/test_analyzer.py::TestFamilyDetection::test_generic_threat_name_is_replaced_with_specific_family
```

Generate coverage reports:

```bash
pytest --cov --cov-report=html --cov-report=term-missing
```

Open `htmlcov/index.html` after the run to inspect uncovered lines.

Run performance benchmarks:

```bash
pytest -m performance --benchmark-only
```

## Fixtures

Common fixtures live in `tests/conftest.py`:

- `emotet_report`, `wannacry_report`, `redline_report`
- `emotet_ioc`, `wannacry_ioc`, `redline_ioc`
- `sample_analysis_result`
- `sample_playbook`
- `flask_test_client`
- `temp_output_dir`
- `mock_anyrun_client`

Prefer these fixtures over recreating large payloads inside each test.

## Guidelines

- Name tests as `test_<function>_<scenario>_<expected_result>` when practical.
- Use `tmp_path` or `temp_output_dir` for file output.
- Mock Any.Run API calls with `responses`; tests must not make real HTTP requests.
- Use `pytest.mark.parametrize` for repeated scenarios.
- Keep integration tests focused on behavior across components, not every branch.

## CI/CD

GitHub Actions is configured in `.github/workflows/tests.yml`. It runs on pushes and pull requests across Python 3.9, 3.10, and 3.11, installs `requirements.txt` and `requirements-dev.txt`, then runs pytest with coverage.

## Troubleshooting

- `ModuleNotFoundError`: run tests from the project root or ensure the root is on `PYTHONPATH`.
- Missing pytest plugin: run `pip install -r requirements-dev.txt`.
- Coverage below threshold: run `pytest --cov-report=term-missing` and add focused tests for uncovered critical branches.
- Slow tests: run `pytest --durations=10` to identify bottlenecks.
- Flask tests writing files unexpectedly: confirm the test uses `flask_test_client`, which changes the working directory to a temporary directory.
