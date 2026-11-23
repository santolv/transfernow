"""Private upload portal + expiring public downloads for blitz.cloud.

Install: pip install -r requirements.txt
Run: ADMIN_PASSWORD='your-long-secret' python app.py
"""
import hmac
import json
import os
import secrets
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote

from flask import Flask, Response, abort, jsonify, render_template_string, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge

DATA = Path(os.getenv('DATA_DIR', '/data')).resolve()
DATA.mkdir(parents=True, exist_ok=True)
FILES = DATA / 'files'
FILES.mkdir(exist_ok=True)
INDEX = DATA / 'index.json'
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '')
if len(ADMIN_PASSWORD) < 16:
    raise RuntimeError('Set ADMIN_PASSWORD with at least 16 characters in blitz.cloud Environment')

DAYS = 7
MAX_BYTES = int(float(os.getenv('MAX_STORAGE_GB', '8')) * 1024**3)
MAX_FILE_BYTES = int(float(os.getenv('MAX_FILE_GB', '4')) * 1024**3)
LOCK = threading.RLock()
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_BYTES + 1024


def read_index():
    if not INDEX.exists():
        return {}
    try:
        with INDEX.open('r', encoding='utf8') as f:
            return json.load(f)
    except (OSError, ValueError):
        raise RuntimeError('Cannot read persistent index.json: refusing to reset it')


def save_index(index):
    tmp = DATA / f'index-{uuid.uuid4().hex}.tmp'
    with tmp.open('w', encoding='utf8') as f:
        json.dump(index, f, ensure_ascii=False)
    os.replace(tmp, INDEX)


def purge_expired():
    with LOCK:
        index = read_index()
        now = time.time()
        expired = [token for token, m in index.items()
                   if m['expires'] <= now or not (FILES / m['id']).is_file()]
        for token in expired:
            (FILES / index[token]['id']).unlink(missing_ok=True)
            del index[token]
        if expired:
            save_index(index)
        # Incomplete uploads never become visible; remove stale temporary files.
        for part in FILES.glob('*.part'):
            if now - part.stat().st_mtime > 2 * 3600:
                part.unlink(missing_ok=True)
        return index


def clean_name(filename):
    filename = filename.replace('\\', '/').split('/')[-1]
    filename = ''.join(c for c in filename if c.isprintable() and c not in '\x00/\\')
    return (filename[:180].strip(' .') or 'archivo')


def auth():
    provided = request.headers.get('X-Admin-Password', '')
    if not hmac.compare_digest(provided.encode('utf8'), ADMIN_PASSWORD.encode('utf8')):
        abort(401, description='Contraseña incorrecta')


@app.after_request
def headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    return response


HTML = '''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Transfer privado</title><style>
:root{color-scheme:dark}body{font:16px system-ui;background:#0e1017;color:#ecedf6;margin:0;padding:32px 16px}.wrap{max-width:720px;margin:auto}h1{font-size:29px}.box{background:#191d29;border:1px solid #343a4b;border-radius:16px;padding:23px;margin:20px 0}input,button{box-sizing:border-box;font:inherit;border-radius:9px;padding:12px;background:#10141f;color:white;border:1px solid #48506a}input[type=password]{width:100%}input[type=file]{width:100%;margin:15px 0}button{background:#526cff;cursor:pointer;border:0}button:disabled{opacity:.5;cursor:default}.muted{color:#a5adc0;font-size:14px}a{color:#9db5ff;word-break:break-all}li{margin:17px 0;word-break:break-word}.row{display:flex;justify-content:space-between;gap:10px;align-items:center}.small{padding:7px 10px}.status{white-space:pre-wrap;word-break:break-word}
</style></head><body><div class="wrap"><h1>📦 Transfer privado</h1><p class="muted">Sube varios archivos. Cada enlace caduca 7 días después de subirlo.</p>
<section class="box"><label for="pass">Contraseña de administrador</label><input id="pass" type="password" autocomplete="off" placeholder="Contraseña configurada en Blitz"><label for="files"><p>Archivos</p></label><input id="files" type="file" multiple><button id="send">Subir archivos</button><p class="status" id="status"></p></section>
<section class="box"><div class="row"><h2>Enlaces generados</h2><button class="small" id="list">Actualizar</button></div><ul id="items"></ul></section><p class="muted">Enlace = permiso de descarga. Compártelo solo con quien corresponda. Máximo 4 GB por archivo y 8 GB totales configurados por defecto.</p></div>
<script>
const $=id=>document.getElementById(id);const pass=()=>$('pass').value;
function liFor(item){const li=document.createElement('li');const label=document.createElement('div');label.textContent=item.name+' · '+(item.size/1024/1024).toFixed(1)+' MB · caduca '+new Date(item.expires*1000).toLocaleString();li.append(label);const a=document.createElement('a');a.href=item.url;a.textContent=item.url;a.target='_blank';a.rel='noreferrer';li.append(a);li.append(document.createTextNode(' '));const copy=document.createElement('button');copy.className='small';copy.textContent='Copiar';copy.onclick=()=>navigator.clipboard.writeText(item.url);li.append(copy);return li}
async function list(){let r=await fetch('/api/files',{headers:{'X-Admin-Password':pass()}});let data=await r.json();if(!r.ok)throw Error(data.error||'Error');$('items').replaceChildren(...data.files.map(liFor));}
$('list').onclick=()=>list().catch(e=>$('status').textContent=e.message);
$('send').onclick=async()=>{const selected=Array.from($('files').files);if(!selected.length){$('status').textContent='Selecciona archivos';return;} $('send').disabled=true;let ok=0;try{for(let i=0;i<selected.length;i++){const f=selected[i];$('status').textContent=`Subiendo ${i+1}/${selected.length}: ${f.name}`;const r=await fetch('/api/upload',{method:'POST',headers:{'X-Admin-Password':pass(),'X-Filename':encodeURIComponent(f.name),'Content-Type':'application/octet-stream'},body:f});const data=await r.json();if(!r.ok)throw Error(f.name+': '+(data.error||'Error'));ok++;$('status').textContent+=` ✓`;} $('files').value='';$('status').textContent=`${ok} archivo(s) subidos correctamente.`;await list();}catch(e){$('status').textContent=`${ok} subidos. Error: ${e.message}`;try{await list()}catch(_){}}finally{$('send').disabled=false;}};
</script></body></html>'''


@app.get('/')
def home():
    return render_template_string(HTML)


@app.get('/health')
def health():
    return jsonify(ok=True)


@app.errorhandler(401)
@app.errorhandler(413)
@app.errorhandler(507)
def error(e):
    return jsonify(error=e.description), e.code


@app.get('/api/files')
def list_files():
    auth()
    index = purge_expired()
    files = [dict(name=v['name'], size=v['size'], expires=v['expires'],
                  url=request.host_url.rstrip('/') + '/d/' + token)
             for token, v in index.items()]
    files.sort(key=lambda x: x['expires'], reverse=True)
    return jsonify(files=files, total_bytes=sum(m['size'] for m in index.values()), max_bytes=MAX_BYTES)


@app.post('/api/upload')
def upload():
    auth()
    filename_header = request.headers.get('X-Filename')
    if not filename_header:
        return jsonify(error='Falta el nombre de archivo'), 400
    filename = clean_name(unquote(filename_header))
    length = request.content_length
    if length is None:
        return jsonify(error='Falta Content-Length'), 411
    if length == 0 or length > MAX_FILE_BYTES:
        return jsonify(error='Archivo vacío o supera el máximo permitido'), 413

    # Serialize uploads to prevent two concurrent requests exceeding the quota.
    with LOCK:
        index = purge_expired()
        used = sum(m['size'] for m in index.values())
        available = min(MAX_BYTES - used, shutil.disk_usage(FILES).free - 64*1024*1024)
        if length > available:
            return jsonify(error='No queda suficiente espacio disponible'), 507
        file_id = uuid.uuid4().hex
        temp = FILES / (file_id + '.part')
        dest = FILES / file_id
        written = 0
        try:
            with temp.open('xb') as out:
                while True:
                    chunk = request.stream.read(min(1024*1024, length - written))
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > length or written > MAX_FILE_BYTES:
                        raise ValueError('Tamaño inesperado')
                    out.write(chunk)
            if written != length:
                raise ValueError('Subida incompleta')
            os.replace(temp, dest)
            token = secrets.token_urlsafe(32)
            expires = time.time() + DAYS*86400
            index[token] = dict(id=file_id, name=filename, size=written, expires=expires)
            save_index(index)
        except (OSError, ValueError) as e:
            temp.unlink(missing_ok=True)
            dest.unlink(missing_ok=True)
            return jsonify(error=f'No se pudo guardar el archivo: {str(e)[:100]}'), 500
    return jsonify(name=filename, size=written, expires=expires,
                   url=request.host_url.rstrip('/') + '/d/' + token), 201


@app.get('/d/<token>')
def download(token):
    with LOCK:
        index = purge_expired()
        record = index.get(token)
        if not record:
            abort(404)
        path = FILES / record['id']
        name = record['name']
    return send_file(path, as_attachment=True, download_name=name, conditional=True)


def janitor():
    while True:
        try:
            purge_expired()
        except Exception:
            app.logger.exception('Cleanup failed')
        time.sleep(3600)


purge_expired()
threading.Thread(target=janitor, daemon=True).start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '8080')), threaded=True)
