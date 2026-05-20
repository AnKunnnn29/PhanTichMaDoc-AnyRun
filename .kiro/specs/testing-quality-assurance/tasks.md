# Implementation Plan: Testing & Quality Assurance

## Overview

This implementation plan creates a comprehensive testing infrastructure for the AnyRun Malware Incident Response Tool using pytest. The plan is organized into 6 phases over 6 weeks, covering infrastructure setup, unit tests, integration tests, performance benchmarks, CI/CD integration, and documentation.

**Target:** 80%+ overall code coverage with 100+ tests across unit, integration, and performance test categories.

## Tasks

- [ ] 1. Infrastructure Setup - Create test directory structure and configuration
  - [ ] 1.1 Create tests/ directory structure with subdirectories
    - Create `tests/` root directory
    - Create `tests/unit/` for unit tests
    - Create `tests/integration/` for integration tests
    - Create `tests/performance/` for performance benchmarks
    - Create `tests/fixtures/` for static test data files
    - _Requirements: 1.1_
  
  - [ ] 1.2 Create pytest.ini configuration file
    - Configure test discovery patterns (test_*.py, *_test.py)
    - Set testpaths to `tests`
    - Configure coverage reporting (HTML, XML, term-missing)
    - Set coverage threshold to 80% (--cov-fail-under=80)
    - Define test markers (unit, integration, performance, slow)
    - _Requirements: 1.3, 10.1, 10.8, 10.9_
  
  - [ ] 1.3 Create requirements-dev.txt with testing dependencies
    - Add pytest>=7.4.0
    - Add pytest-cov>=4.1.0 for coverage
    - Add pytest-mock>=3.11.1 for mocking
    - Add pytest-xdist>=3.3.1 for parallel execution
    - Add responses>=0.23.1 for HTTP mocking
    - Add pytest-flask>=1.2.0 for Flask testing
    - Add pytest-benchmark>=4.0.0 for performance testing
    - Add coverage[toml]>=7.2.7 for coverage reporting
    - _Requirements: 1.2, 1.4_
  
  - [ ] 1.4 Create demo data fixtures in tests/fixtures/
    - Create emotet_report.json with Emotet malware report structure
    - Create wannacry_report.json with WannaCry malware report structure
    - Create redline_report.json with RedLine Stealer report structure
    - Create emotet_ioc.json with Emotet IOC data
    - Create wannacry_ioc.json with WannaCry IOC data
    - Create redline_ioc.json with RedLine IOC data
    - _Requirements: 9.1, 9.2, 9.3_
  
  - [ ] 1.5 Create conftest.py with shared pytest fixtures
    - Implement emotet_report() fixture loading JSON from fixtures/
    - Implement wannacry_report() fixture loading JSON from fixtures/
    - Implement redline_report() fixture loading JSON from fixtures/
    - Implement mock_anyrun_client() fixture with responses library
    - Implement temp_output_dir() fixture using tmp_path
    - Implement flask_test_client() fixture for Flask app testing
    - Implement sample_analysis_result() fixture with MalwareAnalysisResult object
    - Implement sample_playbook() fixture with IncidentResponsePlaybook object
    - _Requirements: 1.6, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9_

- [ ] 2. Checkpoint - Verify infrastructure setup
  - Run `pytest --collect-only` to verify test discovery works
  - Run `pip install -r requirements-dev.txt` to verify dependencies install
  - Verify fixtures load correctly
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 3. Unit Tests - AnyRun Client Module
  - [ ] 3.1 Create tests/unit/test_anyrun_client.py with initialization tests
    - Implement TestAnyRunClientInit class
    - Test client initialization with valid API key
    - Test client initialization with invalid API key raises AnyRunAuthError
    - Test client initialization with empty API key raises appropriate error
    - _Requirements: 2.1_
  
  - [ ] 3.2 Implement GET method tests for AnyRunClient
    - Implement TestAnyRunClientGetMethods class
    - Test get_task_report() with mocked 200 response returns correct data
    - Test get_task_iocs() with mocked 200 response returns correct IOC data
    - Test get_history() with mocked response
    - Use @responses.activate decorator for HTTP mocking
    - _Requirements: 2.2, 2.3, 12.1, 12.2, 12.3_
  
  - [ ] 3.3 Implement error handling tests for AnyRunClient
    - Implement TestAnyRunClientErrorHandling class
    - Test 401 status code raises AnyRunAuthError with appropriate message
    - Test 404 status code raises AnyRunNotFoundError
    - Test 429 status code raises AnyRunRateLimitError
    - Test connection failure raises AnyRunAPIError
    - Test malformed JSON response raises appropriate error
    - _Requirements: 2.4, 2.5, 2.6, 2.7, 13.1_
  
  - [ ] 3.4 Implement POST method tests for AnyRunClient
    - Implement TestAnyRunClientPostMethods class
    - Test submit_file() with valid file path
    - Test submit_file() with non-existent file raises FileNotFoundError
    - Test submit_url() with valid URL
    - _Requirements: 2.8_
  
  - [ ]* 3.5 Verify anyrun_client.py coverage meets 85% target
    - Run `pytest --cov=anyrun_client tests/unit/test_anyrun_client.py`
    - Review coverage report and identify untested code paths
    - Add additional tests for uncovered branches if needed
    - _Requirements: 2.9, 10.3_

- [ ] 4. Unit Tests - Analyzer Module
  - [ ] 4.1 Create tests/unit/test_analyzer.py with malware family detection tests
    - Implement TestMalwareAnalyzerParsing class
    - Test parse_report() with Emotet fixture verifies threat_name is "Emotet"
    - Test parse_report() with WannaCry fixture verifies threat_name and threat_level upgrade
    - Test parse_report() with RedLine fixture verifies threat_name contains "RedLine"
    - Use pytest.mark.parametrize for testing multiple malware families
    - _Requirements: 3.1, 3.2, 3.3_
  
  - [ ] 4.2 Implement MITRE technique extraction tests
    - Implement TestMITREParsing class
    - Test _parse_mitre() extracts all technique IDs from report
    - Test with reports containing 0, 1, 5, and 20 MITRE techniques
    - Verify no technique IDs are lost during parsing
    - _Requirements: 3.4_
  
  - [ ] 4.3 Implement network parsing tests
    - Implement TestNetworkParsing class
    - Test _parse_network() extracts IP addresses without duplicates
    - Test _parse_network() extracts domains without duplicates
    - Test _parse_network() extracts URLs without duplicates
    - Test with reports containing duplicate network IOCs
    - _Requirements: 3.5_
  
  - [ ] 4.4 Implement process and file parsing tests
    - Implement TestProcessParsing class
    - Test _parse_processes() identifies injected processes correctly
    - Test _parse_dropped_files() extracts file hashes and names
    - Test with reports containing multiple injected processes
    - Test with reports containing multiple dropped files
    - _Requirements: 3.6, 3.7_
  
  - [ ] 4.5 Implement family detection heuristics tests
    - Implement TestFamilyDetection class
    - Test _detect_malware_family() with generic threat names
    - Test family detection logic attempts to identify specific families
    - Test with various malware family indicators
    - _Requirements: 3.8_
  
  - [ ]* 4.6 Verify analyzer.py coverage meets 80% target
    - Run `pytest --cov=analyzer tests/unit/test_analyzer.py`
    - Review coverage report and identify untested code paths
    - Add additional tests for uncovered branches if needed
    - _Requirements: 3.9, 10.4_

- [ ] 5. Checkpoint - Verify unit tests for client and analyzer
  - Run `pytest tests/unit/test_anyrun_client.py tests/unit/test_analyzer.py -v`
  - Verify all tests pass
  - Check coverage reports for both modules
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Unit Tests - Incident Response Module
  - [ ] 6.1 Create tests/unit/test_incident_response.py with playbook generation tests
    - Implement TestPlaybookGeneration class
    - Test generate() with threat_level=0 produces LOW severity
    - Test generate() with threat_level=1 produces MEDIUM severity
    - Test generate() with threat_level=2 produces HIGH severity
    - Test generate() with threat_level=3 produces CRITICAL severity
    - Use pytest.mark.parametrize for severity mapping tests
    - _Requirements: 4.1_
  
  - [ ] 6.2 Implement NIST phase completeness tests
    - Implement TestNISTPhases class
    - Test generated playbook includes Identify phase actions
    - Test generated playbook includes Contain phase actions
    - Test generated playbook includes Eradicate phase actions
    - Test generated playbook includes Recover phase actions
    - Test generated playbook includes Lessons Learned phase actions
    - _Requirements: 4.2_
  
  - [ ] 6.3 Implement MITRE-specific action tests
    - Implement TestMITREActions class
    - Test playbook includes network isolation for network IOCs
    - Test playbook includes process termination for injected processes
    - Test playbook includes ransomware actions for T1486
    - Test playbook includes email quarantine for T1566
    - Test playbook includes memory dump actions for T1055
    - Test playbook includes registry cleanup for persistence keys
    - _Requirements: 4.3, 4.4, 4.5, 4.6, 4.7, 4.8_
  
  - [ ] 6.4 Implement IOC blocklist tests
    - Implement TestIOCBlocklist class
    - Test IOC blocklist contains all unique IP addresses
    - Test IOC blocklist contains all unique domains
    - Test IOC blocklist contains all unique file hashes
    - Test blocklist has no duplicates
    - _Requirements: 4.9_
  
  - [ ]* 6.5 Verify incident_response.py coverage meets 75% target
    - Run `pytest --cov=incident_response tests/unit/test_incident_response.py`
    - Review coverage report and identify untested code paths
    - Add additional tests for uncovered branches if needed
    - _Requirements: 4.10, 10.5_

- [ ] 7. Unit Tests - Reporter Module
  - [ ] 7.1 Create tests/unit/test_reporter.py with Markdown export tests
    - Implement TestMarkdownExport class
    - Test export_markdown() creates output file in temp directory
    - Test Markdown report contains valid Markdown syntax
    - Test Markdown report includes malware name
    - Test Markdown report includes severity level
    - Test Markdown report includes MITRE techniques table
    - _Requirements: 5.1, 5.2_
  
  - [ ] 7.2 Implement Markdown content verification tests
    - Test Markdown report includes all IR playbook actions
    - Test actions are grouped by NIST phase
    - Test report includes IOC blocklist section
    - Use temp_output_dir fixture for file I/O
    - _Requirements: 5.3_
  
  - [ ] 7.3 Implement JSON export tests
    - Implement TestJSONExport class
    - Test export_json() creates valid JSON file
    - Test JSON can be parsed back without errors
    - Test JSON contains all required fields (task_uuid, severity, actions, ioc_blocklist)
    - Test JSON round-trip preserves all data
    - _Requirements: 5.4, 5.5_
  
  - [ ] 7.4 Implement behavior narrative tests
    - Implement TestReportContent class
    - Test build_malware_analysis() includes MITRE technique descriptions
    - Test behavior narrative is generated correctly
    - _Requirements: 5.6_
  
  - [ ]* 7.5 Verify reporter.py coverage meets 70% target
    - Run `pytest --cov=reporter tests/unit/test_reporter.py`
    - Review coverage report and identify untested code paths
    - Add additional tests for uncovered branches if needed
    - _Requirements: 5.7, 10.6_

- [ ] 8. Unit Tests - ML Engine Module
  - [ ] 8.1 Create tests/unit/test_ml_engine.py with initialization tests
    - Implement TestMLInitialization class
    - Test MLThreatPredictor initialization without model file sets is_loaded=False
    - Test MLThreatPredictor initialization with model file sets is_loaded=True
    - Test predict() without loaded model returns status="disabled"
    - _Requirements: 6.1, 6.5_
  
  - [ ] 8.2 Implement feature extraction tests
    - Implement TestFeatureExtraction class
    - Test extract_features() returns feature vector with shape (1, 11)
    - Test network features (num_ips, num_domains, num_http) are counted correctly
    - Test MITRE tactic features (has_persistence, has_c2, has_impact) are binary (0 or 1)
    - Test with various analysis results with different IOC counts
    - _Requirements: 6.2, 6.3, 6.4_
  
  - [ ] 8.3 Implement prediction tests with mocked model
    - Implement TestPrediction class
    - Create mock_ml_model fixture using monkeypatch
    - Test predict() returns label in ["Clean", "Suspicious", "Malicious"]
    - Test predict() returns confidence score between 0 and 100
    - Test prediction validation logic
    - _Requirements: 6.6, 6.7_
  
  - [ ]* 8.4 Verify ml_engine.py coverage meets 80% target
    - Run `pytest --cov=ml_engine tests/unit/test_ml_engine.py`
    - Review coverage report and identify untested code paths
    - Add additional tests for uncovered branches if needed
    - _Requirements: 6.8, 10.7_

- [ ] 9. Checkpoint - Verify all unit tests complete
  - Run `pytest tests/unit/ -v` to run all unit tests
  - Verify all unit tests pass
  - Run `pytest --cov --cov-report=html` to generate coverage report
  - Review htmlcov/index.html to check module-specific coverage targets
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Integration Tests - Flask API
  - [ ] 10.1 Create tests/integration/test_flask_api.py with demo endpoint tests
    - Implement TestDemoEndpoints class
    - Test GET /api/demo/emotet returns 200 with valid analysis payload
    - Test GET /api/demo/wannacry returns 200 with WannaCry data
    - Test GET /api/demo/redline returns 200 with RedLine data
    - Verify response JSON contains threat_info with correct threat_name
    - Use flask_test_client fixture
    - _Requirements: 7.1, 7.2, 7.3, 7.10_
  
  - [ ] 10.2 Implement analyze endpoint tests
    - Implement TestAnalyzeEndpoint class
    - Test POST /api/analyze/json with valid report file returns parsed data
    - Test POST /api/analyze/json with empty file returns 400 status
    - Test POST /api/analyze/json with invalid JSON returns 400 status
    - Test error messages are appropriate
    - _Requirements: 7.4, 7.5, 7.6_
  
  - [ ] 10.3 Implement export and history endpoint tests
    - Implement TestExportEndpoint class
    - Test POST /api/export with format="json" creates JSON file
    - Test POST /api/export with format="markdown" creates Markdown file
    - Implement TestHistoryEndpoint class
    - Test GET /api/history/local returns list of analysis history items
    - _Requirements: 7.7, 7.8, 7.9_

- [ ] 11. Integration Tests - CLI
  - [ ] 11.1 Create tests/integration/test_cli.py with demo mode tests
    - Test `python main.py --demo` completes without errors
    - Test demo mode creates both Markdown and JSON reports
    - Test `python main.py --demo --no-export` creates no report files
    - Use subprocess.run() with capture_output=True
    - Verify return code is 0 for successful execution
    - _Requirements: 8.1, 8.2, 8.5, 8.6_
  
  - [ ] 11.2 Implement report-json flag tests
    - Test `python main.py --report-json` with valid file completes successfully
    - Test `python main.py --report-json` with non-existent file shows error message
    - Verify appropriate error messages are displayed
    - _Requirements: 8.3, 8.4_

- [ ] 12. Integration Tests - End-to-End
  - [ ] 12.1 Create tests/integration/test_end_to_end.py with full workflow tests
    - Test complete workflow: load report → analyze → generate playbook → export
    - Test workflow with Emotet demo data
    - Test workflow with WannaCry demo data
    - Test workflow with RedLine demo data
    - Verify all components work together correctly
    - _Requirements: 12.8_

- [ ] 13. Checkpoint - Verify all integration tests complete
  - Run `pytest tests/integration/ -v` to run all integration tests
  - Verify all integration tests pass
  - Check that integration tests complete within 30 seconds
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 14. Performance Tests - Analyzer Benchmarks
  - [ ] 14.1 Create tests/performance/test_analyzer_benchmark.py
    - Implement test_parse_small_report() benchmark with <100KB report
    - Implement test_parse_large_report() benchmark with >1MB report
    - Verify large report parsing completes within 2 seconds
    - Implement test_parse_complex_mitre() benchmark with many MITRE techniques
    - Use pytest-benchmark fixtures
    - _Requirements: 15.1, 15.2_

- [ ] 15. Performance Tests - Reporter Benchmarks
  - [ ] 15.1 Create tests/performance/test_reporter_benchmark.py
    - Implement test_markdown_export_performance() benchmark
    - Verify Markdown export completes within 1 second
    - Implement test_json_export_performance() benchmark
    - Verify JSON export completes within 500ms
    - Implement test_playbook_generation_performance() benchmark
    - Verify playbook generation completes within 500ms
    - _Requirements: 15.3, 15.4_

- [ ] 16. Checkpoint - Verify performance tests complete
  - Run `pytest tests/performance/ -v --benchmark-only`
  - Verify all performance benchmarks pass
  - Review benchmark statistics to ensure performance targets are met
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 17. CI/CD Integration - GitHub Actions
  - [ ] 17.1 Create .github/workflows/tests.yml workflow file
    - Configure workflow to trigger on push to main/develop branches
    - Configure workflow to trigger on pull requests
    - Set up Python 3.9, 3.10, 3.11 matrix
    - Add checkout step using actions/checkout@v3
    - Add Python setup step using actions/setup-python@v4
    - _Requirements: 11.1, 11.2, 11.3, 11.4_
  
  - [ ] 17.2 Configure CI pipeline dependency installation and caching
    - Add pip cache step using actions/cache@v3
    - Add dependency installation step for requirements.txt
    - Add dependency installation step for requirements-dev.txt
    - _Requirements: 11.5_
  
  - [ ] 17.3 Configure CI pipeline test execution and reporting
    - Add test execution step running `pytest --cov --cov-report=xml`
    - Configure workflow to fail if any test fails
    - Add coverage upload step to Codecov (optional)
    - Verify workflow completes within 10 minutes
    - _Requirements: 11.6, 11.7, 11.8, 11.9_

- [ ] 18. Error Handling Tests - Additional Coverage
  - [ ] 18.1 Add error handling tests across all modules
    - Add test for MalwareAnalyzer with missing required fields in report
    - Add test for IncidentResponseGenerator with empty network data
    - Add test for ReportExporter with write permission errors
    - Add test for MLThreatPredictor with unexpected data types
    - Add test for Flask endpoints with missing required parameters
    - _Requirements: 13.2, 13.3, 13.4, 13.5, 13.6, 13.7_

- [ ] 19. Checkpoint - Verify overall coverage meets 80% target
  - Run `pytest --cov --cov-report=html --cov-report=term-missing`
  - Open htmlcov/index.html and review overall coverage
  - Verify overall coverage >= 80%
  - Verify module-specific coverage targets are met
  - Add additional tests for any uncovered critical code paths
  - Ensure all tests pass, ask the user if questions arise.
  - _Requirements: 10.2_

- [ ] 20. Test Documentation
  - [ ] 20.1 Create tests/README.md with comprehensive test documentation
    - Document test organization and directory structure
    - Add instructions for running all tests with `pytest`
    - Add instructions for running specific test files or functions
    - Add instructions for generating coverage reports
    - Add instructions for running tests in CI/CD
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_
  
  - [ ] 20.2 Add test guidelines and troubleshooting section
    - Document guidelines for writing new test cases
    - Explain test fixtures and how to use them
    - Add troubleshooting section for common test failures
    - Document how to run unit tests only with `pytest -m unit`
    - Document how to run integration tests only with `pytest -m integration`
    - _Requirements: 14.6, 14.7, 14.8_

- [ ] 21. Final Checkpoint - Complete validation
  - Run full test suite with `pytest -v`
  - Verify all 100+ tests pass
  - Verify coverage >= 80% overall
  - Verify CI/CD pipeline runs successfully
  - Verify test execution time < 60 seconds locally
  - Review all documentation is complete
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional verification tasks that can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at key milestones
- Unit tests should be fast (<1s per module) and isolated
- Integration tests may take longer (1-5s per module) but should still be efficient
- Performance tests use pytest-benchmark to measure execution time
- All tests use mocked external dependencies (no real API calls)
- Test fixtures are shared via conftest.py to avoid duplication
- CI/CD pipeline tests on Python 3.9, 3.10, and 3.11 for compatibility
- Overall implementation timeline: 6 weeks (1 week per major phase)

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2", "1.3"] },
    { "id": 1, "tasks": ["1.4", "1.5"] },
    { "id": 2, "tasks": ["3.1", "4.1"] },
    { "id": 3, "tasks": ["3.2", "3.3", "4.2", "4.3"] },
    { "id": 4, "tasks": ["3.4", "3.5", "4.4", "4.5", "4.6"] },
    { "id": 5, "tasks": ["6.1", "7.1", "8.1"] },
    { "id": 6, "tasks": ["6.2", "6.3", "7.2", "8.2"] },
    { "id": 7, "tasks": ["6.4", "6.5", "7.3", "7.4", "7.5", "8.3", "8.4"] },
    { "id": 8, "tasks": ["10.1", "11.1"] },
    { "id": 9, "tasks": ["10.2", "10.3", "11.2", "12.1"] },
    { "id": 10, "tasks": ["14.1", "15.1"] },
    { "id": 11, "tasks": ["17.1"] },
    { "id": 12, "tasks": ["17.2", "17.3"] },
    { "id": 13, "tasks": ["18.1"] },
    { "id": 14, "tasks": ["20.1", "20.2"] }
  ]
}
```
