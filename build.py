"""Build the data blob for the register page from the run data (run.json and the exports beside it) plus the BSI catalog and ISO mapping."""
import json, re, sys
src, cat_path, map_path, tpl_path, out_path = sys.argv[1:6]
J = lambda p: json.load(open(p, encoding='utf-8'))
titles = J(f'{src}/titles.json'); ctext = J(f'{src}/catalog-text.json')
cat = J(cat_path)['catalog']; mc = J(map_path)['mapping-collection']

# full catalog index
C, parent = {}, {}
def walk(ctrls, p):
    for c in ctrls or []:
        C[c['id']] = c; parent[c['id']] = p; walk(c.get('controls'), c['id'])
def groups(gs):
    for g in gs or []:
        walk(g.get('controls'), None); groups(g.get('groups'))
groups(cat.get('groups'))
links = lambda c, rel: [l['href'].lstrip('#') for l in c.get('links', []) if l.get('rel') == rel]
req_by = {}
for i, c in C.items():
    for t in links(c, 'required'): req_by.setdefault(t, []).append(i)
rel_back = {}
for i, c in C.items():
    for t in links(c, 'related'): rel_back.setdefault(t, []).append(i)
iso, iso_idx = {}, {}
for mp in mc['mappings']:
    for m in mp['maps']:
        for s in m['sources']:
            for t in m['targets']:
                iso.setdefault(t['id-ref'], []).append({'id': s['id-ref'], 'rel': m['relationship']})
                iso_idx.setdefault(s['id-ref'], []).append({'id': t['id-ref'], 'rel': m['relationship']})
def stmt(c):
    own = {p['id']: (p.get('label') or ' / '.join(p.get('values', []))) for p in c.get('params', [])}
    pr = next((p.get('prose', '') for p in c.get('parts', []) if p.get('name') == 'statement'), '')
    return re.sub(r'\{\{\s*insert:\s*param,\s*([\w.-]+)\s*\}\}', lambda m: '„' + own.get(m.group(1), m.group(1)) + '“', pr)

runs = []
for line in open(f'{src}/runs.txt'):
    pid, md, hm, st, sha = line.split()
    runs.append({'id': int(pid), 'd': '2026-' + md, 't': hm, 'ok': st == 's', 'sha': sha})
checks = []
for line in open(f'{src}/checks.txt'):
    cid, method, rq, title = [x.strip() for x in line.split('|')]
    checks.append({'id': cid, 'm': method, 'r': rq.split(','), 't': title})
trial = open(f'{src}/trial.txt').read().split()
poam = {}
for line in open(f'{src}/poam.txt'):
    parts = [x.strip() for x in line.rstrip('\n').split('|')]
    rid, _, na, dl, rem = (parts + [''] * 5)[:5]
    acts = [{'id': m.group(1), 'x': m.group(2).strip()} for m in re.finditer(r'(I-\d+): (.*?)(?=; I-\d+:|$)', rem)]
    poam[rid] = {'na': na == 'NA', 'dl': dl or None, 'a': acts}

reqs, order = {}, []
for line in open(f'{src}/ssp.txt'):
    rid, st, asm, rest = line.rstrip('\n').split(' ', 3)
    t, k, c = titles.get(rid, {}), ctext[rid], C.get(rid, {})
    order.append(rid)
    reqs[rid] = {'t': t.get('t', ''), 'g': t.get('g', ''), 'gt': t.get('gt', ''), 's': t.get('s', ''), 'stt': t.get('st', ''),
                 'st': st, 'm': asm == 's', 'c': [] if rest == '-' else [x.strip() for x in rest.split(',')],
                 'stm': k['stm'], 'mv': k['mv'], 'doc': k['doc'], 'gdn': k['gdn'], 'lvl': k['lvl'],
                 'thr': [x.strip() for x in k['thr'].split(',') if x.strip()],
                 'p': parent.get(rid), 'k': [x['id'] for x in c.get('controls', [])],
                 'req': links(c, 'required'), 'reqBy': req_by.get(rid, []),
                 'rel': sorted(set(links(c, 'related')) | set(rel_back.get(rid, []))),
                 'iso': iso.get(rid, []), 'poam': poam.get(rid)}
# catalog-only entries that the profile's requirements or the ISO index point at
need = set()
for r in reqs.values():
    need.update(x for x in [r['p'], *r['k'], *r['req'], *r['reqBy'], *r['rel']] if x)
for s in {i['id'] for r in reqs.values() for i in r['iso']}:
    need.update(x['id'] for x in iso_idx[s])
ext = {i: {'t': C[i].get('title', ''), 'stm': stmt(C[i]), 'p': parent.get(i)} for i in sorted(need) if i not in reqs and i in C}
# the run being shown (id, sha, date, time, project) comes with the run data
data = {'run': J(f'{src}/run.json'),
        'catalog': '367d775010abee641b258926bb482fcd05270059', 'runs': runs, 'order': order, 'reqs': reqs, 'ext': ext,
        'checks': checks, 'trial': trial, 'iso': {s: iso_idx[s] for s in sorted({i['id'] for r in reqs.values() for i in r['iso']})}}
html = open(tpl_path, encoding='utf-8').read().replace('/*__DATA__*/null', json.dumps(data, ensure_ascii=False, separators=(',', ':')))
open(out_path, 'w', encoding='utf-8').write(html)
print(len(html), len(reqs), len(ext), len(data['iso']))
