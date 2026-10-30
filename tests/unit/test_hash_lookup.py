import json
import requests
import responses
import pytest
from hash_lookup import ENDPOINT,NOT_FOUND,lookup_hash,answer_lookup,_cache
from ai_assistant import answer_remediation,answer_remediation_stream

SHA='a'*64

@pytest.fixture(autouse=True)
def lookup_env(monkeypatch):
    _cache.clear();monkeypatch.setenv('MALWAREBAZAAR_AUTH_KEY','test-secret-placeholder')
    yield
    _cache.clear()

@responses.activate
def test_found_metadata_uses_auth_header_and_read_only_query():
    responses.post(ENDPOINT,json={'query_status':'ok','data':[{'sha256_hash':SHA,'file_name':'example.exe','signature':'ExampleFamily','tags':['sample'],'file_type':'exe'}]})
    result=lookup_hash(SHA)
    assert result['status']=='found' and result['family']=='ExampleFamily'
    sent=responses.calls[0].request
    assert sent.headers['Auth-Key']=='test-secret-placeholder'
    assert sent.body=='query=get_info&hash='+SHA
    assert 'test-secret-placeholder' not in json.dumps(result)
    assert lookup_hash(SHA)==result and len(responses.calls)==1

@responses.activate
def test_not_found_has_approved_text_and_no_provider_name():
    responses.post(ENDPOINT,json={'query_status':'hash_not_found'})
    answer=answer_lookup('Tra cứu '+SHA,{})
    assert answer['answer']==NOT_FOUND
    assert 'malwarebazaar' not in answer['answer'].lower()
    assert answer['sources']==[]

@pytest.mark.parametrize('status,expected',[(401,'auth_error'),(403,'auth_error'),(429,'rate_limited'),(503,'unavailable')])
@responses.activate
def test_service_errors_are_not_reported_as_missing_hash(status,expected):
    responses.post(ENDPOINT,status=status)
    assert lookup_hash(SHA)['status']==expected

@responses.activate
def test_timeout_and_mismatched_hash_are_not_missing_data():
    responses.post(ENDPOINT,body=requests.Timeout('do not echo credentials'))
    assert lookup_hash(SHA)['status']=='unavailable'
    responses.replace(responses.POST,ENDPOINT,json={'query_status':'ok','data':[{'sha256_hash':'b'*64}]})
    assert lookup_hash(SHA)['status']=='unavailable'

@responses.activate
def test_json_and_stream_share_lookup_result_without_llm(monkeypatch):
    monkeypatch.setenv('AI_PROVIDER','ollama')
    responses.post(ENDPOINT,json={'query_status':'hash_not_found'})
    result=answer_remediation('Tra cứu '+SHA,{})
    events=list(answer_remediation_stream('Tra cứu '+SHA,{}))
    assert result['mode']=='hash_lookup'
    assert events[0]['mode']=='hash_lookup'
    assert ''.join(e.get('text','') for e in events)==NOT_FOUND
    assert len(responses.calls)==1

@responses.activate
def test_chat_can_lookup_without_open_case(flask_test_client):
    responses.post(ENDPOINT,json={'query_status':'hash_not_found'})
    response=flask_test_client.post('/api/ai/remediation',json={'question':SHA})
    assert response.status_code==200 and response.json['answer']==NOT_FOUND
    stream=flask_test_client.post('/api/ai/remediation/stream',json={'question':SHA})
    assert stream.status_code==200 and NOT_FOUND in stream.get_data(as_text=True)

def test_invalid_hash_and_missing_key_do_not_call_service(monkeypatch):
    assert lookup_hash('not-a-hash')['status']=='invalid_hash'
    monkeypatch.delenv('MALWAREBAZAAR_AUTH_KEY')
    assert lookup_hash(SHA)['status']=='not_configured'

@pytest.mark.parametrize('question,expected',[
    (SHA,True),
    ('Tra cứu '+SHA,True),
    ('sha256: '+SHA+' ?',True),
    ('Tra cứu mã băm của tệp trong hồ sơ này',True),
    ('Tệp này là mã độc gì?',True),
    ('Cần tra cứu thêm log nào trên EDR?',False),
    ('Hash này đã xuất hiện trên máy nào, cần cô lập không?',False),
    ('Hash '+SHA+' đã xuất hiện trên máy nào, cần cô lập không?',False),
    ('Tôi nên xử lý theo thứ tự ưu tiên nào?',False),
])
def test_lookup_only_for_explicit_requests(question,expected):
    from hash_lookup import lookup_requested
    assert lookup_requested(question) is expected


def _case_payload():
    def ev(path, value, ctx):
        return {'type': 'sha256', 'source_path': path, 'value': value, 'context': ctx}
    return {'file': {'name': 'bundle.zip', 'sha256': 'a' * 64},
            'evidence_bundle': {'evidence': [
                ev('/data/content/mainObject/hashes/sha256', 'a' * 64, {}),
                ev('/data/content/dropped/0/hashes/sha256', 'b' * 64, {'filename': r'C:\Temp\__PSScriptPolicyTest_x.ps1', 'type': 'executable'}),
                ev('/data/content/dropped/1/hashes/sha256', 'c' * 64, {'filename': r'C:\Temp\notes.txt', 'type': 'text'}),
                ev('/data/content/dropped/2/hashes/sha256', 'd' * 64, {'filename': r'C:\Temp\payload.exe', 'type': 'executable'})]}}


def test_case_candidates_are_main_sample_then_dropped_executables():
    from hash_lookup import case_hash_candidates
    assert [h for _, h in case_hash_candidates(_case_payload())] == ['a' * 64, 'd' * 64]


@responses.activate
def test_case_lookup_falls_through_container_to_dropped_payload():
    def reply(request):
        if 'a' * 64 in request.body:
            return (200, {}, json.dumps({'query_status': 'hash_not_found'}))
        return (200, {}, json.dumps({'query_status': 'ok', 'data': [{'sha256_hash': 'd' * 64, 'file_name': 'Install.exe',
                                                                      'signature': 'WannaCry', 'tags': ['ransomware']}]}))
    responses.add_callback(responses.POST, ENDPOINT, callback=reply)
    result = answer_lookup('Tra cứu mã băm của tệp trong hồ sơ này', _case_payload())
    assert [t['status'] for t in result['tried']] == ['not_found', 'found']
    assert 'Mẫu chính bundle.zip' in result['answer'] and 'payload.exe khớp bản ghi' in result['answer']
    assert 'WannaCry' in result['answer'] and result['lookup']['hash'] == 'd' * 64
