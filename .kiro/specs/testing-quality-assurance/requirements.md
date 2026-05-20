# Requirements Document

## Introduction

Dự án AnyRun Malware Incident Response Tool hiện tại không có test suite, gây khó khăn trong việc đảm bảo chất lượng code và phát hiện regression bugs khi phát triển tính năng mới. Tài liệu này định nghĩa các yêu cầu để xây dựng comprehensive testing infrastructure với pytest, bao gồm unit tests, integration tests, và quality metrics nhằm đạt 80%+ code coverage.

## Glossary

- **Test_Suite**: Tập hợp các test cases được tổ chức theo module và loại test (unit, integration)
- **Test_Fixture**: Dữ liệu mẫu hoặc mock objects được sử dụng để thiết lập môi trường test
- **Code_Coverage**: Tỷ lệ phần trăm code được thực thi bởi test suite
- **Mock_Object**: Đối tượng giả lập thay thế dependencies thực (API calls, file I/O) trong tests
- **CI_Pipeline**: Continuous Integration pipeline tự động chạy tests khi có code changes
- **Pytest**: Python testing framework được sử dụng cho dự án
- **Test_Runner**: Công cụ thực thi test suite (pytest)
- **Assertion**: Câu lệnh kiểm tra kết quả thực tế so với kết quả mong đợi
- **Integration_Test**: Test kiểm tra tương tác giữa nhiều components
- **Unit_Test**: Test kiểm tra một function/class độc lập

## Requirements

### Requirement 1: Test Infrastructure Setup

**User Story:** Là một developer, tôi muốn có test infrastructure cơ bản với pytest, để tôi có thể bắt đầu viết và chạy tests.

#### Acceptance Criteria

1. THE Test_Suite SHALL be organized in a `tests/` directory mirroring the source code structure
2. THE Test_Runner SHALL use pytest framework with pytest-cov for coverage reporting
3. THE Test_Suite SHALL include pytest configuration file (`pytest.ini` or `pyproject.toml`) with test discovery settings
4. THE Test_Suite SHALL include requirements file (`requirements-dev.txt`) listing all testing dependencies
5. WHEN a developer runs `pytest`, THE Test_Runner SHALL discover and execute all test files matching pattern `test_*.py` or `*_test.py`
6. THE Test_Suite SHALL include conftest.py with shared fixtures for demo data and mock objects

### Requirement 2: AnyRun Client Unit Tests

**User Story:** Là một developer, tôi muốn test anyrun_client.py với mocked API responses, để đảm bảo API client xử lý đúng các responses và errors.

#### Acceptance Criteria

1. WHEN AnyRunClient is initialized with invalid API key, THE Test_Suite SHALL verify AnyRunAuthError is raised
2. WHEN `get_task_report()` is called with valid task UUID, THE Mock_Object SHALL return demo report data and THE Test_Suite SHALL verify correct parsing
3. WHEN `get_task_iocs()` is called with valid task UUID, THE Mock_Object SHALL return demo IOC data and THE Test_Suite SHALL verify correct parsing
4. IF API returns 401 status code, THEN THE Test_Suite SHALL verify AnyRunAuthError is raised with appropriate message
5. IF API returns 404 status code, THEN THE Test_Suite SHALL verify AnyRunNotFoundError is raised
6. IF API returns 429 status code, THEN THE Test_Suite SHALL verify AnyRunRateLimitError is raised
7. IF API connection fails, THEN THE Test_Suite SHALL verify AnyRunAPIError is raised with connection error message
8. WHEN `submit_file()` is called with non-existent file path, THE Test_Suite SHALL verify FileNotFoundError is raised
9. THE Test_Suite SHALL achieve minimum 85% code coverage for anyrun_client.py module

### Requirement 3: Analyzer Unit Tests

**User Story:** Là một developer, tôi muốn test analyzer.py với các malware families khác nhau, để đảm bảo parsing logic hoạt động đúng cho Emotet, WannaCry, và RedLine.

#### Acceptance Criteria

1. WHEN MalwareAnalyzer parses Emotet demo report, THE Test_Suite SHALL verify threat_name is correctly identified as "Emotet"
2. WHEN MalwareAnalyzer parses WannaCry demo report, THE Test_Suite SHALL verify threat_name is "WannaCry" and threat_level is upgraded to 3 or higher
3. WHEN MalwareAnalyzer parses RedLine demo report, THE Test_Suite SHALL verify threat_name contains "RedLine"
4. WHEN MalwareAnalyzer parses report with MITRE techniques, THE Test_Suite SHALL verify all technique IDs are extracted correctly
5. WHEN MalwareAnalyzer parses report with network activity, THE Test_Suite SHALL verify IP addresses, domains, and URLs are extracted without duplicates
6. WHEN MalwareAnalyzer parses report with process injection, THE Test_Suite SHALL verify injected_processes list is populated correctly
7. WHEN MalwareAnalyzer parses report with dropped files, THE Test_Suite SHALL verify file hashes and names are extracted
8. WHEN MalwareAnalyzer parses report with generic threat name, THE Test_Suite SHALL verify family detection logic attempts to identify specific malware family
9. THE Test_Suite SHALL achieve minimum 80% code coverage for analyzer.py module

### Requirement 4: Incident Response Generator Unit Tests

**User Story:** Là một developer, tôi muốn test incident_response.py logic, để đảm bảo playbook generation tạo đúng actions theo NIST phases và MITRE techniques.

#### Acceptance Criteria

1. WHEN IncidentResponseGenerator generates playbook for malicious sample (threat_level >= 2), THE Test_Suite SHALL verify severity is "HIGH" or "CRITICAL"
2. WHEN IncidentResponseGenerator generates playbook, THE Test_Suite SHALL verify all NIST IR phases are represented (Identify, Contain, Eradicate, Recover, Lessons)
3. WHEN analysis result contains network IOCs, THE Test_Suite SHALL verify playbook includes network isolation actions with firewall commands
4. WHEN analysis result contains injected processes, THE Test_Suite SHALL verify playbook includes process termination actions
5. WHEN analysis result contains MITRE T1486 (ransomware), THE Test_Suite SHALL verify playbook includes critical priority ransomware-specific actions
6. WHEN analysis result contains MITRE T1566 (phishing), THE Test_Suite SHALL verify playbook includes email quarantine actions
7. WHEN analysis result contains MITRE T1055 (process injection), THE Test_Suite SHALL verify playbook includes memory dump actions
8. WHEN analysis result contains persistence registry keys, THE Test_Suite SHALL verify playbook includes registry cleanup actions
9. THE Test_Suite SHALL verify IOC blocklist contains all unique IPs, domains, and file hashes from analysis result
10. THE Test_Suite SHALL achieve minimum 75% code coverage for incident_response.py module

### Requirement 5: Reporter Unit Tests

**User Story:** Là một developer, tôi muốn test reporter.py export functions, để đảm bảo Markdown và JSON reports được tạo đúng format.

#### Acceptance Criteria

1. WHEN ReportExporter exports Markdown report, THE Test_Suite SHALL verify output file exists and contains valid Markdown syntax
2. WHEN ReportExporter exports Markdown report, THE Test_Suite SHALL verify report includes malware name, severity, and MITRE techniques table
3. WHEN ReportExporter exports Markdown report, THE Test_Suite SHALL verify report includes all IR playbook actions grouped by NIST phase
4. WHEN ReportExporter exports JSON report, THE Test_Suite SHALL verify output is valid JSON and can be parsed back
5. WHEN ReportExporter exports JSON report, THE Test_Suite SHALL verify JSON contains all required fields (task_uuid, severity, actions, ioc_blocklist)
6. WHEN `build_malware_analysis()` is called, THE Test_Suite SHALL verify behavior narrative includes relevant MITRE technique descriptions
7. THE Test_Suite SHALL achieve minimum 70% code coverage for reporter.py module

### Requirement 6: ML Engine Unit Tests

**User Story:** Là một developer, tôi muốn test ml_engine.py prediction logic, để đảm bảo feature extraction và model inference hoạt động đúng.

#### Acceptance Criteria

1. WHEN MLThreatPredictor is initialized without model file, THE Test_Suite SHALL verify is_loaded is False
2. WHEN MLThreatPredictor extracts features from analysis result, THE Test_Suite SHALL verify feature vector has correct shape (1, 11)
3. WHEN MLThreatPredictor extracts features, THE Test_Suite SHALL verify network features (num_ips, num_domains, num_http) are counted correctly
4. WHEN MLThreatPredictor extracts features, THE Test_Suite SHALL verify MITRE tactic features (has_persistence, has_c2, has_impact) are binary (0 or 1)
5. WHEN MLThreatPredictor predicts without loaded model, THE Test_Suite SHALL return status "disabled" with appropriate message
6. WHERE model file exists, WHEN MLThreatPredictor predicts, THE Test_Suite SHALL verify prediction returns label in ["Clean", "Suspicious", "Malicious"]
7. WHERE model file exists, WHEN MLThreatPredictor predicts, THE Test_Suite SHALL verify confidence score is between 0 and 100
8. THE Test_Suite SHALL achieve minimum 80% code coverage for ml_engine.py module

### Requirement 7: Flask API Integration Tests

**User Story:** Là một developer, tôi muốn test Flask endpoints, để đảm bảo web API hoạt động đúng với các request scenarios.

#### Acceptance Criteria

1. WHEN client requests `/api/demo/emotet`, THE Test_Suite SHALL verify response status is 200 and contains valid analysis payload
2. WHEN client requests `/api/demo/wannacry`, THE Test_Suite SHALL verify response contains WannaCry-specific data
3. WHEN client requests `/api/demo/redline`, THE Test_Suite SHALL verify response contains RedLine-specific data
4. WHEN client POSTs to `/api/analyze/json` with valid report file, THE Test_Suite SHALL verify response contains parsed analysis data
5. WHEN client POSTs to `/api/analyze/json` with empty report file, THE Test_Suite SHALL verify response status is 400 with error message
6. WHEN client POSTs to `/api/analyze/json` with invalid JSON, THE Test_Suite SHALL verify response status is 400
7. WHEN client POSTs to `/api/export` with format "json", THE Test_Suite SHALL verify JSON file is created in reports directory
8. WHEN client POSTs to `/api/export` with format "markdown", THE Test_Suite SHALL verify Markdown file is created in reports directory
9. WHEN client GETs `/api/history/local`, THE Test_Suite SHALL verify response contains list of local analysis history items
10. THE Test_Suite SHALL use pytest-flask fixtures for Flask test client setup

### Requirement 8: CLI Integration Tests

**User Story:** Là một developer, tôi muốn test main.py CLI commands, để đảm bảo command-line interface hoạt động đúng.

#### Acceptance Criteria

1. WHEN user runs `python main.py --demo`, THE Test_Suite SHALL verify demo analysis completes without errors
2. WHEN user runs `python main.py --demo --no-export`, THE Test_Suite SHALL verify no report files are created
3. WHEN user runs `python main.py --report-json` with valid file, THE Test_Suite SHALL verify analysis completes successfully
4. WHEN user runs `python main.py --report-json` with non-existent file, THE Test_Suite SHALL verify appropriate error message is displayed
5. WHEN demo mode completes, THE Test_Suite SHALL verify both Markdown and JSON reports are created in output directory
6. THE Test_Suite SHALL use subprocess or click.testing.CliRunner for CLI testing

### Requirement 9: Test Fixtures and Demo Data

**User Story:** Là một developer, tôi muốn có reusable test fixtures, để tránh duplicate code và dễ dàng maintain test data.

#### Acceptance Criteria

1. THE Test_Suite SHALL include pytest fixture providing Emotet demo report and IOC data
2. THE Test_Suite SHALL include pytest fixture providing WannaCry demo report and IOC data
3. THE Test_Suite SHALL include pytest fixture providing RedLine demo report and IOC data
4. THE Test_Suite SHALL include pytest fixture providing mock AnyRunClient with responses library
5. THE Test_Suite SHALL include pytest fixture providing temporary directory for file output tests
6. THE Test_Suite SHALL include pytest fixture providing Flask test client
7. THE Test_Suite SHALL include pytest fixture providing sample MalwareAnalysisResult objects
8. THE Test_Suite SHALL include pytest fixture providing sample IncidentResponsePlaybook objects
9. WHEN fixtures are used across multiple test files, THE Test_Suite SHALL define them in conftest.py for sharing

### Requirement 10: Code Coverage Requirements

**User Story:** Là một developer, tôi muốn đo lường code coverage, để biết phần nào của code chưa được test.

#### Acceptance Criteria

1. WHEN developer runs `pytest --cov`, THE Test_Runner SHALL generate coverage report for all source modules
2. THE Test_Suite SHALL achieve minimum 80% overall code coverage across all modules
3. THE Test_Suite SHALL achieve minimum 85% coverage for anyrun_client.py (critical API integration)
4. THE Test_Suite SHALL achieve minimum 80% coverage for analyzer.py (core parsing logic)
5. THE Test_Suite SHALL achieve minimum 75% coverage for incident_response.py (playbook generation)
6. THE Test_Suite SHALL achieve minimum 70% coverage for reporter.py (output formatting)
7. THE Test_Suite SHALL achieve minimum 80% coverage for ml_engine.py (ML predictions)
8. WHEN coverage report is generated, THE Test_Runner SHALL output HTML coverage report to `htmlcov/` directory
9. WHEN coverage is below target threshold, THE Test_Runner SHALL fail with exit code 1 (configurable via pytest.ini)

### Requirement 11: CI/CD Integration

**User Story:** Là một developer, tôi muốn tests tự động chạy trên GitHub Actions, để phát hiện bugs sớm trước khi merge code.

#### Acceptance Criteria

1. THE CI_Pipeline SHALL be defined in `.github/workflows/tests.yml` file
2. WHEN code is pushed to any branch, THE CI_Pipeline SHALL trigger test execution automatically
3. WHEN pull request is created, THE CI_Pipeline SHALL run tests and report status on PR
4. THE CI_Pipeline SHALL test on Python 3.9, 3.10, and 3.11 versions
5. THE CI_Pipeline SHALL install dependencies from requirements.txt and requirements-dev.txt
6. THE CI_Pipeline SHALL run `pytest --cov --cov-report=xml` to generate coverage report
7. THE CI_Pipeline SHALL upload coverage report to Codecov or similar service (optional)
8. IF any test fails, THEN THE CI_Pipeline SHALL fail with non-zero exit code and block PR merge
9. THE CI_Pipeline SHALL complete within 10 minutes for typical test suite execution

### Requirement 12: Mock External Dependencies

**User Story:** Là một developer, tôi muốn mock external API calls và file I/O, để tests chạy nhanh và không phụ thuộc vào external services.

#### Acceptance Criteria

1. WHEN tests call AnyRunClient methods, THE Mock_Object SHALL intercept HTTP requests using responses library
2. WHEN tests call `get_task_report()`, THE Mock_Object SHALL return predefined JSON response without real API call
3. WHEN tests call `get_task_iocs()`, THE Mock_Object SHALL return predefined IOC data without real API call
4. WHEN tests write files, THE Test_Fixture SHALL provide temporary directory that is cleaned up after test
5. WHEN tests read files, THE Test_Fixture SHALL provide sample files from `tests/fixtures/` directory
6. THE Test_Suite SHALL NOT make real HTTP requests to any.run API during test execution
7. THE Test_Suite SHALL NOT require valid API key to run tests
8. THE Test_Suite SHALL complete full test run in under 30 seconds on typical development machine

### Requirement 13: Error Handling Tests

**User Story:** Là một developer, tôi muốn test error handling paths, để đảm bảo application xử lý lỗi gracefully.

#### Acceptance Criteria

1. WHEN AnyRunClient receives malformed JSON response, THE Test_Suite SHALL verify appropriate error is raised
2. WHEN MalwareAnalyzer receives report with missing required fields, THE Test_Suite SHALL verify parsing continues with default values
3. WHEN IncidentResponseGenerator receives analysis result with empty network data, THE Test_Suite SHALL verify playbook is still generated
4. WHEN ReportExporter cannot write to output directory, THE Test_Suite SHALL verify appropriate exception is raised
5. WHEN MLThreatPredictor receives analysis result with unexpected data types, THE Test_Suite SHALL verify prediction returns error status
6. WHEN Flask endpoint receives request with missing required parameters, THE Test_Suite SHALL verify 400 status code is returned
7. THE Test_Suite SHALL test at least one error path for each major function in each module

### Requirement 14: Test Documentation

**User Story:** Là một developer, tôi muốn có documentation về test suite, để hiểu cách chạy tests và thêm test cases mới.

#### Acceptance Criteria

1. THE Test_Suite SHALL include README.md in `tests/` directory explaining test organization
2. THE Test_Suite documentation SHALL include instructions for running all tests with `pytest`
3. THE Test_Suite documentation SHALL include instructions for running specific test file or test function
4. THE Test_Suite documentation SHALL include instructions for generating coverage report
5. THE Test_Suite documentation SHALL include instructions for running tests in CI/CD
6. THE Test_Suite documentation SHALL include guidelines for writing new test cases
7. THE Test_Suite documentation SHALL include explanation of test fixtures and how to use them
8. THE Test_Suite documentation SHALL include troubleshooting section for common test failures

### Requirement 15: Performance and Regression Tests

**User Story:** Là một developer, tôi muốn có performance benchmarks, để phát hiện performance regressions khi thay đổi code.

#### Acceptance Criteria

1. THE Test_Suite SHALL include benchmark tests for analyzer parsing performance using pytest-benchmark
2. WHEN analyzer parses large report (>1MB JSON), THE Test_Suite SHALL verify parsing completes within 2 seconds
3. WHEN incident response generator creates playbook, THE Test_Suite SHALL verify generation completes within 500ms
4. WHEN reporter exports Markdown report, THE Test_Suite SHALL verify export completes within 1 second
5. THE Test_Suite SHALL include regression tests verifying critical bug fixes remain fixed
6. WHERE performance benchmark exists, WHEN code changes cause >20% performance degradation, THE Test_Suite SHALL fail with warning message
