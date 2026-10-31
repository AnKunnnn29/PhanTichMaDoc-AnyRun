"""Read the same anonymous task metadata used by the public ANY.RUN client.

No credentials, browser profiles, solver services or sample downloads are used.
"""
import json
import re
import time


class PublicTaskLookupError(ValueError):
    pass


def _session():
    from curl_cffi import Session
    return Session(impersonate='chrome')


def fetch_public_page(url):
    with _session() as client:
        return client.get(url, timeout=18, max_redirects=3)


def resolve_public_task(task_uuid):
    if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',task_uuid):
        raise PublicTaskLookupError('Task ID không hợp lệ.')
    with _session() as client:
        with client.ws_connect('wss://app.any.run/websocket',headers={'Origin':'https://app.any.run'},timeout=8) as socket:
            socket.send_str(json.dumps({'msg':'connect','version':'1','support':['1']}))
            started=time.monotonic();sent=False
            for _ in range(32):
                remaining=16-(time.monotonic()-started)
                if remaining<=0:break
                raw=socket.recv_str(timeout=min(remaining,6))
                if len(raw)>2000000:raise PublicTaskLookupError('Phản hồi metadata vượt giới hạn.')
                packet=json.loads(raw)
                if not isinstance(packet,dict):raise PublicTaskLookupError('Metadata không hợp lệ.')
                if packet.get('msg')=='connected' and not sent:
                    socket.send_str(json.dumps({'msg':'method','method':'getTaskByUUID','params':[task_uuid],'id':'public-task'}));sent=True
                elif packet.get('msg')=='ping':
                    socket.send_str(json.dumps({'msg':'pong','id':packet.get('id')}))
                elif packet.get('msg')=='failed':
                    raise PublicTaskLookupError('Any.Run chưa chấp nhận kết nối đọc task công khai.')
                elif packet.get('msg')=='result' and packet.get('id')=='public-task':
                    if packet.get('error'):raise PublicTaskLookupError('Any.Run không cho phép đọc task này ở chế độ công khai. Kiểm tra liên kết hoặc quyền truy cập.')
                    task=packet.get('result')
                    if not isinstance(task,dict) or task.get('uuid')!=task_uuid:
                        raise PublicTaskLookupError('Metadata trả về không khớp Task ID.')
                    public=task.get('public') or {}
                    if public.get('options',{}).get('private') not in ('public','bylink'):
                        raise PublicTaskLookupError('Task không được xác nhận là công khai hoặc chia sẻ bằng liên kết. Cần quyền đọc tương ứng.')
                    sha=public.get('objects',{}).get('mainObject',{}).get('hashes',{}).get('sha256','')
                    if not isinstance(sha,str) or not re.fullmatch('[0-9a-fA-F]{64}',sha):
                        raise PublicTaskLookupError('Task chưa có SHA256 để mở báo cáo đầy đủ; có thể đang chạy hoặc không phải mẫu tệp.')
                    return 'https://any.run/report/'+sha.lower()+'/'+task_uuid
    raise PublicTaskLookupError('Hết thời gian chờ metadata của task công khai. Thử lại sau.')
