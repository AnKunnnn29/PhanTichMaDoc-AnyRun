"""Rebuild the small family baseline from the exact source pinned by attack_catalog.json."""
from pathlib import Path
import hashlib
import json

import requests

ROOT = Path(__file__).resolve().parents[1]


def main():
    meta = json.loads((ROOT / 'data/attack_catalog.json').read_text(encoding='utf-8'))
    response = requests.get(meta['source_url'], timeout=60)
    response.raise_for_status()
    if hashlib.sha256(response.content).hexdigest() != meta['source_sha256']:
        raise ValueError('ATT&CK source differs from the pinned catalogue; review the version before updating.')
    objects = response.json()['objects']
    by_id = {o['id']: o for o in objects}
    def active(o):
        return not o.get('revoked') and not o.get('x_mitre_deprecated')
    def ref(o):
        return next(x for x in o['external_references'] if x.get('source_name') == 'mitre-attack')
    families = {}
    for software in objects:
        if software.get('type') != 'malware' or software.get('name') not in {'WannaCry','Emotet','RedLine Stealer'} or not active(software):
            continue
        external = ref(software)
        techniques = []
        for relation in objects:
            if relation.get('type') != 'relationship' or relation.get('relationship_type') != 'uses' or relation.get('source_ref') != software['id'] or not active(relation):
                continue
            technique = by_id.get(relation.get('target_ref'), {})
            if technique.get('type') != 'attack-pattern' or not active(technique):
                continue
            target = ref(technique)
            techniques.append({'id': target['external_id'], 'name': technique['name'], 'url': target.get('url',''), 'relationship_id': relation['id']})
        families[software['name']] = {'software_id': external['external_id'], 'url': external['url'],
                                      'aliases': software.get('x_mitre_aliases', []),
                                      'techniques': sorted(techniques, key=lambda t: t['id'])}
    if len(families) != 3:
        raise ValueError('The pinned source does not contain all three expected software entries.')
    output = {k: meta[k] for k in ('version','source_url','source_sha256')}
    output['families'] = families
    (ROOT / 'data/family_expectations.json').write_text(json.dumps(output, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print('Updated family expectations from the verified ATT&CK source.')


if __name__ == '__main__':
    main()
