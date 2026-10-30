"""Read-only hash intelligence; missing data is never a clean verdict."""
import hashlib
import os
import re
import threading
import time
import unicodedata
import requests

ENDPOINT='https://mb-api.abuse.ch/api/v1/'
NOT_FOUND='Chưa tìm thấy thông tin về mã băm này trong nguồn tra cứu. Kết quả này chưa đủ để kết luận tệp an toàn hay độc hại.'
HASH_RE=re.compile(r'(?<![a-zA-Z0-9])[a-fA-F0-9]{64}(?![a-zA-Z0-9])|(?<![a-zA-Z0-9])[a-fA-F0-9]{40}(?![a-zA-Z0-9])|(?<![a-zA-Z0-9])[a-fA-F0-9]{32}(?![a-zA-Z0-9])')
_cache={}
_lock=threading.Lock()


EXPLICIT_TERMS=('tra cuu ma bam','tra cuu hash','lookup hash','nhan dien tep','tep nay la ma doc gi','file nay la ma doc gi')


def lookup_requested(question):
    # Only explicit lookups: a bare hash, "tra cứu <hash>" or a lookup phrase.
    # Remediation questions that merely mention "hash" or "tra cứu" stay with the assistant.
    q=''.join(c for c in unicodedata.normalize('NFD',str(question).lower().replace('đ','d')) if unicodedata.category(c)!='Mn')
    if any(term in q for term in EXPLICIT_TERMS):return True
    if not HASH_RE.search(q):return False
    rest=re.sub(r'[^\w\s]',' ',HASH_RE.sub(' ',q)).split()
    return len(rest)<=3 or 'tra cuu' in q


def select_hash(question,payload):
    match=HASH_RE.search(question)
    if match:return match.group().lower()
    file=payload.get('file') or {}
    for kind,size in (('sha256',64),('sha1',40),('md5',32)):
        value=file.get(kind,'')
        if isinstance(value,str) and re.fullmatch('[a-fA-F0-9]{'+str(size)+'}',value):return value.lower()
    return ''


def configured():
    return bool(os.getenv('MALWAREBAZAAR_AUTH_KEY','').strip())


def lookup_hash(value):
    value=str(value).lower().strip()
    if not re.fullmatch(r'(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})',value):
        return {'status':'invalid_hash','hash':value}
    key=os.getenv('MALWAREBAZAAR_AUTH_KEY','').strip()
    if not key:return {'status':'not_configured','hash':value}
    cache_key=(hashlib.sha256(key.encode()).hexdigest(),value)
    with _lock:
        cached=_cache.get(cache_key)
        if cached and cached[0]>time.monotonic():return dict(cached[1])
    try:
        response=requests.post(ENDPOINT,headers={'Auth-Key':key},data={'query':'get_info','hash':value},timeout=(4,10))
        if response.status_code in (401,403):return {'status':'auth_error','hash':value}
        if response.status_code==429:return {'status':'rate_limited','hash':value}
        if response.status_code!=200:return {'status':'unavailable','hash':value}
        body=response.json()
        if not isinstance(body,dict):return {'status':'unavailable','hash':value}
        status=body.get('query_status')
        if status in ('no_api_key','invalid_api_key','user_blacklisted','auth_required','invalid_auth_key'):
            return {'status':'auth_error','hash':value}
        if status=='hash_not_found':result={'status':'not_found','hash':value}
        elif status=='ok' and isinstance(body.get('data'),list) and body['data']:
            field={32:'md5_hash',40:'sha1_hash',64:'sha256_hash'}[len(value)]
            row=next((r for r in body['data'] if isinstance(r,dict) and str(r.get(field,'')).lower()==value),None)
            if row is None:return {'status':'unavailable','hash':value}
            clean=lambda name: str(row.get(name) or '')[:500].replace('\n',' ').replace('\r',' ')
            sha=clean('sha256_hash').lower()
            if not re.fullmatch('[a-f0-9]{64}',sha):return {'status':'unavailable','hash':value}
            result={'status':'found','hash':value,'sha256':sha,'file_name':clean('file_name'),
                    'family':clean('signature'),'file_type':clean('file_type'),
                    'first_seen':clean('first_seen'),'last_seen':clean('last_seen'),
                    'tags':[str(t)[:80].replace('\n',' ') for t in (row.get('tags') or [])[:12]] if isinstance(row.get('tags'),list) else [],
                    'source_url':'https://bazaar.abuse.ch/sample/'+sha+'/','retrieved_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
        else:return {'status':'unavailable','hash':value}
    except (requests.RequestException,ValueError,TypeError,KeyError):
        return {'status':'unavailable','hash':value}
    with _lock:
        now=time.monotonic()
        for item in [k for k,v in _cache.items() if v[0]<=now]:_cache.pop(item,None)
        if len(_cache)>=128:_cache.pop(next(iter(_cache)))
        _cache[cache_key]=(now+300,dict(result))
    return result


def format_lookup(result):
    status=result['status']
    if status=='not_found':return NOT_FOUND
    messages={
        'invalid_hash':'Hãy nhập mã SHA256, SHA1 hoặc MD5 hợp lệ, hoặc mở hồ sơ có mã băm của tệp.',
        'not_configured':'Chức năng tra cứu chưa được cấu hình trên máy chủ này.',
        'auth_error':'Khóa truy cập nguồn tra cứu chưa được chấp nhận. Cần kiểm tra cấu hình máy chủ.',
        'rate_limited':'Nguồn tra cứu đang giới hạn số yêu cầu. Vui lòng thử lại sau.',
        'unavailable':'Chưa kết nối được nguồn tra cứu hoặc chưa xác minh được phản hồi. Vui lòng thử lại sau; chưa thể kết luận về tệp.'}
    if status!='found':return messages.get(status,messages['unavailable'])
    return '\n'.join(['Đã tìm thấy thông tin đối chiếu cho mã băm này.',
        'Tên tệp được ghi nhận: '+(result['file_name'] or 'Chưa có'),
        'Họ mã độc / nhãn nhận diện: '+(result['family'] or 'Chưa xác định'),
        'Loại tệp: '+(result['file_type'] or 'Chưa có'),
        'Nhãn liên quan: '+(', '.join(result['tags']) or 'Chưa có'),
        'Ghi nhận đầu tiên (UTC): '+(result['first_seen'] or 'Chưa có'),
        'Ghi nhận gần nhất (UTC): '+(result['last_seen'] or 'Chưa có'),
        'Đây là dữ liệu tham chiếu bên ngoài, không xác nhận endpoint của bạn đã nhiễm. Đối chiếu với bằng chứng trong hồ sơ trước khi xử lý.'])


MAX_CASE_LOOKUPS=4
EXECUTABLE_EXT=('.exe','.dll','.scr','.sys','.bat','.ps1','.vbs','.js','.msi')


def case_hash_candidates(payload):
    """The opened case's main sample first, then executables it dropped (a .zip container is rarely indexed itself)."""
    candidates=[]
    main=select_hash('',payload)
    if main:candidates.append(('Mẫu chính '+str((payload.get('file') or {}).get('name') or ''),main))
    for row in (payload.get('evidence_bundle') or {}).get('evidence',[]):
        ctx=row.get('context') or {}
        name=str(ctx.get('filename',''))
        if row.get('type')!='sha256' or '/dropped/' not in str(row.get('source_path','')):continue
        if ctx.get('type')!='executable' and not name.lower().endswith(EXECUTABLE_EXT):continue
        if '__PSScriptPolicyTest_' in name:continue
        value=str(row.get('value','')).lower()
        if re.fullmatch('[a-f0-9]{64}',value) and value not in {h for _,h in candidates}:
            candidates.append(('Tệp thực thi do mẫu tạo ra '+name,value))
    return candidates


def answer_lookup(question,payload):
    if HASH_RE.search(question) or not payload:
        result=lookup_hash(select_hash(question,payload))
        return {'mode':'hash_lookup','model':'hash-intelligence','answer':format_lookup(result),
                'lookup':result,'sources':[result['source_url']] if result.get('source_url') else []}
    tried=[]
    for label,value in case_hash_candidates(payload)[:MAX_CASE_LOOKUPS]:
        result=lookup_hash(value)
        tried.append((label,result))
        if result['status'] in ('found','not_configured','auth_error','rate_limited'):break
    if not tried:
        result={'status':'invalid_hash','hash':''}
        return {'mode':'hash_lookup','model':'hash-intelligence','answer':format_lookup(result),'lookup':result,'sources':[]}
    label,result=next(((l,r) for l,r in tried if r['status']=='found'),tried[-1])
    lines=[f'{l.strip()} ({r["hash"][:12]}…): chưa có trong nguồn tra cứu.' for l,r in tried if r['status']=='not_found' and r is not result]
    if result['status']=='found':
        lines.append(f'{label.strip()} khớp bản ghi trong nguồn tra cứu:')
    answer='\n'.join(lines+[format_lookup(result)])
    return {'mode':'hash_lookup','model':'hash-intelligence','answer':answer,'lookup':result,
            'tried':[{'label':l,'hash':r['hash'],'status':r['status']} for l,r in tried],
            'sources':[result['source_url']] if result.get('source_url') else []}
