#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import html
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

TEXT_EXTENSIONS = {'.txt','.log','.md','.markdown','.csv','.tsv','.json','.jsonl','.xml','.yaml','.yml','.ini','.cfg','.conf','.html','.htm','.xhtml','.css','.js','.mjs','.cjs','.ts','.tsx','.jsx','.vue','.svelte','.php','.php3','.php4','.php5','.phtml','.asp','.aspx','.jsp','.jspx','.py','.rb','.go','.java','.c','.h','.cpp','.hpp','.rs','.sh','.bash','.zsh','.fish','.sql','.toml','.properties','.env','.graphql','.gql','.svg'}
TEXT_FILENAMES = {'Dockerfile','Makefile','README','LICENSE','.gitignore','.htaccess','.env','robots.txt','security.txt','sitemap.xml'}
SKIP_DIRS = {'.git','.svn','.hg','__pycache__','node_modules','.venv','venv','env','.idea','.vscode'}

URL_RE = re.compile(r"https?://[^\s<>\"'`\]\[)]+", re.I)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
HTML_LINK_RE = re.compile(r'''(?is)\b(?:href|src)\s*=\s*["']([^"']+)["']''')
INTERESTING_PATTERNS = {
    'API-key-like': re.compile(r'''(?i)\b(?:api[_-]?key|apikey|access[_-]?token|client[_-]?secret|auth[_-]?token|secret[_-]?key)\b\s*[:=]\s*['"]?[^'"\s,;]{8,}'''),
    'JWT-like': re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
    'Private-key-marker': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'Password-assignment': re.compile(r'''(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*['"][^'"]{1,200}['"]'''),
}

def now_iso():
    return dt.datetime.now().astimezone().isoformat(timespec='seconds')

def human_size(n):
    units=['B','KB','MB','GB','TB']; x=float(n)
    for u in units:
        if x < 1024 or u == units[-1]:
            return f'{x:.1f} {u}' if u != 'B' else f'{int(x)} B'
        x /= 1024
    return f'{n} B'

def sha256_file(path, chunk_size=1024*1024):
    h=hashlib.sha256()
    try:
        with path.open('rb') as f:
            while True:
                b=f.read(chunk_size)
                if not b: break
                h.update(b)
        return h.hexdigest()
    except Exception as e:
        return f'ERROR: {e}'

def is_probably_text(path, sample_size=8192):
    if path.name in TEXT_FILENAMES or path.suffix.lower() in TEXT_EXTENSIONS: return True
    try:
        with path.open('rb') as f: sample=f.read(sample_size)
        if not sample or b'\x00' in sample: return not sample or b'\x00' not in sample
        try: sample.decode('utf-8'); return True
        except UnicodeDecodeError:
            printable=sum(1 for c in sample if c in (9,10,13) or 32 <= c <= 126)
            return printable/max(1,len(sample)) > .85
    except Exception: return False

def safe_read_text(path, max_bytes):
    try:
        with path.open('rb') as f: data=f.read(max_bytes+1)
        truncated=len(data)>max_bytes
        if truncated: data=data[:max_bytes]
        return data.decode('utf-8',errors='replace'),truncated,None
    except Exception as e: return '',False,str(e)

def extract_urls(text):
    out=set()
    for m in URL_RE.finditer(text):
        u=m.group(0).rstrip('.,;:!?')
        if u.lower().startswith(('http://','https://')): out.add(u)
    return sorted(out)

def extract_html_links(text):
    return sorted({m.group(1).strip() for m in HTML_LINK_RE.finditer(text) if m.group(1).strip().startswith(('http://','https://'))})

def line_numbers(text, pattern, limit=30):
    out=[]
    for m in pattern.finditer(text):
        out.append(text.count('\n',0,m.start())+1)
        if len(out)>=limit: break
    return out

def firefox_path():
    for p in [shutil.which('firefox'),'/usr/bin/firefox','/usr/local/bin/firefox']:
        if p and Path(p).exists(): return p
    return None

def open_in_firefox(items, delay=.15):
    ff=firefox_path()
    if not ff:
        print('[!] Firefox was not found in PATH.'); return False
    for item in items:
        try:
            subprocess.Popen([ff,'--new-tab',str(item)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            time.sleep(delay)
        except Exception as e: print(f'[!] Could not open {item}: {e}')
    return True

def collect(root, max_read_mb, no_hash=False):
    max_bytes=max(1,max_read_mb)*1024*1024
    files=[]; folders=[]; urls=set(); html_files=[]; interesting=[]; errors=[]
    total_size=text_files=binary_files=0
    def onerror(err): errors.append(str(err))
    for current, dirnames, filenames in os.walk(root, followlinks=False, onerror=onerror):
        current_path=Path(current); dirnames[:]=sorted(d for d in dirnames if d not in SKIP_DIRS)
        if current_path != root: folders.append(str(current_path.relative_to(root)))
        for name in sorted(filenames):
            p=current_path/name
            try:
                st=p.stat(); size=st.st_size; total_size+=size; rel=str(p.relative_to(root)); kind_text=is_probably_text(p)
                item={'path':rel,'size':size,'size_human':human_size(size),'modified':dt.datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(timespec='seconds'),'extension':p.suffix.lower(),'text':kind_text,'sha256':'SKIPPED' if no_hash else sha256_file(p),'urls':[],'emails':[],'interesting':[],'truncated':False,'read_error':None}
                if kind_text:
                    text_files+=1; text,truncated,err=safe_read_text(p,max_bytes); item['truncated']=truncated; item['read_error']=err
                    if err: errors.append(f'{rel}: {err}')
                    else:
                        found_urls=set(extract_urls(text))
                        if p.suffix.lower() in {'.html','.htm','.xhtml','.svg'}:
                            found_urls.update(extract_html_links(text)); html_files.append(rel)
                        item['urls']=sorted(found_urls); urls.update(found_urls); item['emails']=sorted(set(EMAIL_RE.findall(text)))[:100]
                        for label,pattern in INTERESTING_PATTERNS.items():
                            lines=line_numbers(text,pattern)
                            if lines:
                                item['interesting'].append({'type':label,'lines':lines}); interesting.append({'file':rel,'type':label,'lines':lines})
                else: binary_files+=1
                files.append(item)
            except Exception as e: errors.append(f'{p}: {e}')
    return {'root':str(root.resolve()),'generated':now_iso(),'files':files,'folders':sorted(folders),'urls':sorted(urls),'html_files':sorted(set(html_files)),'interesting':interesting,'errors':errors,'total_size':total_size,'text_files':text_files,'binary_files':binary_files}

def esc(x): return html.escape(str(x),quote=True)

def make_report(data, output):
    files=data['files']; urls=data['urls']; interesting=data['interesting']
    ext_counts={}
    for f in files:
        ext=f['extension'] or '[no extension]'; ext_counts[ext]=ext_counts.get(ext,0)+1
    largest=sorted(files,key=lambda x:x['size'],reverse=True)[:20]
    file_rows=[]
    for f in files:
        flags=[]
        if f['urls']: flags.append(f"{len(f['urls'])} URL(s)")
        if f['interesting']: flags.extend(x['type'] for x in f['interesting'])
        if f['truncated']: flags.append('read capped')
        if f['read_error']: flags.append('read error')
        file_rows.append('<tr>'+f"<td><code>{esc(f['path'])}</code></td><td>{esc(f['size_human'])}</td><td>{'Text' if f['text'] else 'Binary/unknown'}</td><td>{esc(f['modified'])}</td><td><code>{esc(f['sha256'])}</code></td><td>{esc(', '.join(flags) if flags else '—')}</td>"+'</tr>')
    url_rows=[]
    for u in urls:
        p=urlparse(u); url_rows.append('<tr>'+f"<td><a href='{esc(u)}' target='_blank' rel='noopener noreferrer'>{esc(u)}</a></td><td>{esc(p.netloc)}</td><td>{esc(p.path or '/')}</td>"+'</tr>')
    interesting_rows=['<tr>'+f"<td><code>{esc(x['file'])}</code></td><td>{esc(x['type'])}</td><td>{esc(', '.join(map(str,x['lines'])))}</td>"+'</tr>' for x in interesting]
    largest_rows=['<tr>'+f"<td><code>{esc(f['path'])}</code></td><td>{esc(f['size_human'])}</td><td><code>{esc(f['sha256'])}</code></td>"+'</tr>' for f in largest]
    ext_rows=''.join(f"<tr><td><code>{esc(k)}</code></td><td>{v}</td></tr>" for k,v in sorted(ext_counts.items(),key=lambda x:(-x[1],x[0])))
    doc=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Bug-Hunting File Report</title><style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#111827;color:#e5e7eb;margin:0}}main{{max-width:1500px;margin:auto;padding:28px}}h1,h2{{color:#fff}}.card{{background:#1f2937;border:1px solid #374151;border-radius:12px;padding:18px;margin:16px 0;overflow:auto}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}}.stat{{background:#111827;border-radius:10px;padding:14px}}.stat b{{display:block;font-size:24px;color:#fff}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:9px;border-bottom:1px solid #374151;text-align:left;vertical-align:top}}th{{position:sticky;top:0;background:#111827}}code{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-word}}a{{color:#93c5fd}}.note{{color:#9ca3af}}input{{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #4b5563;background:#111827;color:#fff;margin:8px 0 12px}}</style><script>function filterTable(i,t){{const q=document.getElementById(i).value.toLowerCase();document.querySelectorAll('#'+t+' tbody tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')}}</script></head><body><main>
<h1>Bug-Hunting File &amp; URL Report</h1><p class="note">Generated: {esc(data['generated'])}<br>Root: <code>{esc(data['root'])}</code></p>
<div class="grid"><div class="stat">Files<b>{len(files)}</b></div><div class="stat">Folders<b>{len(data['folders'])}</b></div><div class="stat">Text files read<b>{data['text_files']}</b></div><div class="stat">Binary/unknown<b>{data['binary_files']}</b></div><div class="stat">URLs found<b>{len(urls)}</b></div><div class="stat">Total size<b>{esc(human_size(data['total_size']))}</b></div></div>
<div class="card"><h2>Scope &amp; limitations</h2><ul><li>Recursive inventory except common dependency/cache directories: <code>{esc(', '.join(sorted(SKIP_DIRS)))}</code>.</li><li>Text files are read up to the configured per-file limit.</li><li>Binary files are inventoried and hashed but not decoded.</li><li>Large text files may be marked <b>read capped</b>.</li><li>Interesting matches are indicators only, not proof of vulnerabilities or exposed secrets.</li><li>This script does not make network requests to discovered URLs.</li></ul></div>
<div class="card"><h2>Interesting indicators</h2><p class="note">Only file/line locations are shown; potentially sensitive matched values are not copied.</p><table><thead><tr><th>File</th><th>Indicator</th><th>Line(s)</th></tr></thead><tbody>{''.join(interesting_rows) or '<tr><td colspan="3">None found</td></tr>'}</tbody></table></div>
<div class="card"><h2>Discovered HTTP/HTTPS URLs ({len(urls)})</h2><input id="urlFilter" onkeyup="filterTable('urlFilter','urlTable')" placeholder="Filter URLs..."><table id="urlTable"><thead><tr><th>URL</th><th>Host</th><th>Path</th></tr></thead><tbody>{''.join(url_rows) or '<tr><td colspan="3">No HTTP/HTTPS URLs found</td></tr>'}</tbody></table></div>
<div class="card"><h2>Largest files</h2><table><thead><tr><th>File</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>{''.join(largest_rows)}</tbody></table></div>
<div class="card"><h2>File inventory ({len(files)})</h2><input id="fileFilter" onkeyup="filterTable('fileFilter','fileTable')" placeholder="Filter files..."><table id="fileTable"><thead><tr><th>Path</th><th>Size</th><th>Type</th><th>Modified</th><th>SHA-256</th><th>Flags</th></tr></thead><tbody>{''.join(file_rows)}</tbody></table></div>
<div class="card"><h2>Extension summary</h2><table><thead><tr><th>Extension</th><th>Count</th></tr></thead><tbody>{ext_rows}</tbody></table></div>
<div class="card"><h2>HTML pages found</h2><ul>{''.join(f'<li><code>{esc(x)}</code></li>' for x in data['html_files']) or '<li>None</li>'}</ul></div>
<div class="card"><h2>Scan errors</h2><ul>{''.join(f'<li><code>{esc(x)}</code></li>' for x in data['errors']) or '<li>None</li>'}</ul></div>
</main></body></html>'''
    output.write_text(doc,encoding='utf-8'); return output

def main():
    ap=argparse.ArgumentParser(description='Recursively scan a project and create an HTML report.')
    ap.add_argument('root',nargs='?',default='.',help='Directory to scan')
    ap.add_argument('-o','--output',default='bug_hunting_report.html',help='Output HTML file')
    ap.add_argument('--max-read-mb',type=int,default=8,help='Maximum text read per file in MB')
    ap.add_argument('--open-report',action='store_true',help='Open report in Firefox')
    ap.add_argument('--open-html',action='store_true',help='Open discovered local HTML pages in Firefox')
    ap.add_argument('--open-urls',action='store_true',help='Open discovered URLs in Firefox')
    ap.add_argument('--yes',action='store_true',help='Do not ask before opening URLs')
    ap.add_argument('--no-hash',action='store_true',help='Skip SHA-256 hashing')
    args=ap.parse_args(); root=Path(args.root).expanduser().resolve()
    if not root.is_dir(): print(f'[!] Not a directory: {root}'); sys.exit(2)
    print(f'[*] Scanning: {root}\n[*] Large datasets may take a while...')
    data=collect(root,args.max_read_mb,args.no_hash); output=Path(args.output).expanduser()
    if not output.is_absolute(): output=root/output
    output.parent.mkdir(parents=True,exist_ok=True); make_report(data,output)
    print('\n[+] Scan complete'); print(f"[+] Files: {len(data['files'])}"); print(f"[+] Folders: {len(data['folders'])}"); print(f"[+] Text files read: {data['text_files']}"); print(f"[+] URLs found: {len(data['urls'])}"); print(f"[+] HTML files: {len(data['html_files'])}"); print(f"[+] Interesting indicators: {len(data['interesting'])}"); print(f'[+] Report: {output}')
    if args.open_html and data['html_files']: print(f"[*] Opening {len(data['html_files'])} local HTML file(s) in Firefox..."); open_in_firefox([root/x for x in data['html_files']])
    if args.open_urls and data['urls']:
        print(f"\n[!] {len(data['urls'])} HTTP/HTTPS URL(s) found."); print('[!] Opening them can create many tabs and contact external sites.')
        approved=args.yes or input('Open ALL discovered URLs in Firefox? [y/N]: ').strip().lower() in {'y','yes'}
        if approved: open_in_firefox(data['urls'])
        else: print('[*] URLs were not opened.')
    if args.open_report: open_in_firefox([output])

if __name__=='__main__': main()
