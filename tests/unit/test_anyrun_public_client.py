import json
import pytest
import anyrun_public_client as client

TASK='4a4f9f51-083f-47e7-9d1d-424bfcdbbeea'
SHA='a'*64

class FakeSocket:
    def __init__(self,task):
        self.messages=iter([{'msg':'connected'},{'msg':'ping','id':'keepalive'},{'msg':'result','id':'public-task','result':task}])
        self.sent=[]
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def send_str(self,value):self.sent.append(json.loads(value))
    def recv_str(self,timeout):return json.dumps(next(self.messages))

class FakeSession:
    def __init__(self,socket):self.socket=socket
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def ws_connect(self,url,**kwargs):
        assert url=='wss://app.any.run/websocket'
        assert kwargs['headers']=={'Origin':'https://app.any.run'}
        return self.socket

def task(privacy='public',uuid=TASK):
    return {'uuid':uuid,'public':{'options':{'private':privacy},'objects':{'mainObject':{'hashes':{'sha256':SHA}}}}}

def test_public_metadata_resolves_same_task_without_login(monkeypatch):
    socket=FakeSocket(task());monkeypatch.setattr(client,'_session',lambda:FakeSession(socket))
    assert client.resolve_public_task(TASK)=='https://any.run/report/'+SHA+'/'+TASK
    methods=[m for m in socket.sent if m.get('msg')=='method']
    assert methods==[{'msg':'method','method':'getTaskByUUID','params':[TASK],'id':'public-task'}]
    assert any(m.get('msg')=='pong' for m in socket.sent)

@pytest.mark.parametrize('privacy',['owner','byteam',None])
def test_does_not_use_metadata_of_private_tasks(monkeypatch,privacy):
    monkeypatch.setattr(client,'_session',lambda:FakeSession(FakeSocket(task(privacy))))
    with pytest.raises(client.PublicTaskLookupError,match='quyền đọc'):client.resolve_public_task(TASK)

def test_rejects_mismatched_task_metadata(monkeypatch):
    monkeypatch.setattr(client,'_session',lambda:FakeSession(FakeSocket(task(uuid='different-task'))))
    with pytest.raises(client.PublicTaskLookupError,match='không khớp'):client.resolve_public_task(TASK)
