import os
import json
import hmac
import hashlib
import secrets
import requests
import boto3
from botocore.client import Config
from functools import wraps
from urllib.parse import unquote
from datetime import timedelta
import os
import json
import hmac
import hashlib
import secrets
import requests
import boto3
from botocore.client import Config
from functools import wraps
from urllib.parse import unquote
from datetime import timedelta

from flask import (
Flask, render_template, request, jsonify,
session, redirect, url_for, abort, Response, stream_with_context
)
from models import db, User, Song

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=90)
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True

DATABASE_URL = os.environ.get('DATABASE_URL', '')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///hertmusic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024

BOT_TOKEN = os.environ.get('BOT_TOKEN', '')
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', secrets.token_hex(16))

_raw_ids = os.environ.get('ADMIN_TELEGRAM_IDS', os.environ.get('ADMIN_TELEGRAM_ID', ''))
ADMIN_IDS = {s.strip() for s in _raw_ids.split(',') if s.strip()}
ADMIN_USERNAMES = {'zawarkayt', 'bread6942'}
_raw_unames = os.environ.get('ADMIN_USERNAMES', '')
if _raw_unames:
    ADMIN_USERNAMES = {s.strip().lstrip('@').lower() for s in _raw_unames.split(',') if s.strip()}

# ─────────────────────────── S3 / Railway Bucket ───────────────────────────

# Railway AWS-style bucket variables

S3_ENDPOINT   = os.environ.get('AWS_ENDPOINT_URL_S3') or os.environ.get('RAILWAY_BUCKET_ENDPOINT_URL', '')
S3_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY_ID') or os.environ.get('RAILWAY_BUCKET_ACCESS_KEY_ID', '')
S3_SECRET_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY') or os.environ.get('RAILWAY_BUCKET_SECRET_ACCESS_KEY', '')
S3_REGION     = os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('RAILWAY_BUCKET_REGION', 'auto')
S3_BUCKET     = os.environ.get('BUCKET_NAME') or os.environ.get('AWS_BUCKET_NAME') or os.environ.get('RAILWAY_BUCKET_NAME', '')

def get_s3():
    return boto3.client(
        's3',
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        region_name=S3_REGION,
        config=Config(signature_version='s3v4')
    )

def s3_upload(file_bytes: bytes, key: str, content_type: str) -> str | None:
    """Upload bytes to S3, return public URL or None on error."""
    try:
        s3 = get_s3()
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=file_bytes,
            ContentType=content_type,
        )
        # Build public URL
        url = f'{S3_ENDPOINT.rstrip("/")}/{S3_BUCKET}/{key}'
        print(f'[S3] uploaded {key} → {url}', flush=True)
        return url
    except Exception as e:
        print(f'[S3] upload error: {e}', flush=True)
        return None

def s3_presign(key: str, expires: int = 3600) -> str | None:
    """Generate presigned URL for private object."""
    try:
        s3 = get_s3()
        url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': S3_BUCKET, 'Key': key},
            ExpiresIn=expires
        )
        return url
    except Exception as e:
        print(f'[S3] presign error: {e}', flush=True)
        return None

def s3_delete(key: str):
    try:
        s3 = get_s3()
        s3.delete_object(Bucket=S3_BUCKET, Key=key)
    except Exception as e:
        print(f'[S3] delete error: {e}', flush=True)

db.init_app(app)
with app.app_context():
    db.create_all()

# ─────────────────────────── Telegram helpers ──────────────────────────────

def tg(method, **kwargs):
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/{method}'
    try:
        r = requests.post(url, json=kwargs, timeout=15)
        return r.json()
    except Exception as e:
        print(f'[TG] {method} error: {e}', flush=True)
        return {}

def notify_admins(text, reply_markup=None):
    for admin_id in ADMIN_IDS:
        kwargs = dict(chat_id=admin_id, text=text, parse_mode='HTML')
        if reply_markup:
            kwargs['reply_markup'] = reply_markup
        tg('sendMessage', **kwargs)

# ─────────────────────────── Auth helpers ──────────────────────────────────

def verify_tg_webapp(init_data_raw: str):
    if not BOT_TOKEN:
        return True, {}
    try:
        parsed = dict(
            pair.split('=', 1)
            for pair in unquote(init_data_raw).split('&')
            if '=' in pair
        )
        received_hash = parsed.pop('hash', '')
        data_check = '\n'.join(f'{k}={v}' for k, v in sorted(parsed.items()))
        secret_key = hmac.new(b'WebAppData', BOT_TOKEN.encode(), hashlib.sha256).digest()
        computed = hmac.new(secret_key, data_check.encode(), hashlib.sha256).hexdigest()
        valid = hmac.compare_digest(computed, received_hash)
        user_data = json.loads(parsed.get('user', '{}'))
        return valid, user_data
    except Exception as e:
        print(f'[Auth] verify error: {e}', flush=True)
        return False, {}

def is_admin_user(user) -> bool:
    if not user:
        return False
    if str(user.telegram_id) in ADMIN_IDS:
        return True
    uname = (user.telegram_username or '').lower().lstrip('@')
    return uname in ADMIN_USERNAMES

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = db.session.get(User, session['user_id'])
        if not is_admin_user(user):
            abort(403)
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    uid = session.get('user_id')
    return db.session.get(User, uid) if uid else None

# ─────────────────────────── Pages ─────────────────────────────────────────

@app.route('/')
def index():
    user = get_current_user()
    songs = Song.query.filter_by(status='approved').order_by(Song.created_at.desc()).all()
    return render_template('index.html', user=user, songs=songs, is_admin=is_admin_user(user))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if get_current_user():
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        user = User.query.filter_by(token=token).first()
        if user:
            session.permanent = True
            session['user_id'] = user.id
            return redirect(url_for('index'))
        error = 'Неверный токен'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    user = get_current_user()
    error = None
    success = None

    if request.method == 'POST':
        title  = request.form.get('title', '').strip()
        artist = request.form.get('artist', '').strip()
        cover_file = request.files.get('cover')
        audio_file = request.files.get('audio')

        print(f'[UPLOAD] title={repr(title)} artist={repr(artist)} cover={getattr(cover_file,"filename",None)} audio={getattr(audio_file,"filename",None)}', flush=True)
        print(f'[S3] bucket={S3_BUCKET} endpoint={S3_ENDPOINT}', flush=True)

        if not all([title, artist, cover_file, audio_file]):
            error = 'Заполни все поля'
        elif not S3_BUCKET or not S3_ENDPOINT:
            error = 'S3 bucket не настроен. Проверь переменные в Railway.'
        else:
            song_id_tmp = secrets.token_hex(8)

            # Upload cover
            cover_bytes = cover_file.read()
            cover_ext = (cover_file.filename or 'cover.jpg').rsplit('.', 1)[-1].lower()
            cover_key = f'covers/{song_id_tmp}.{cover_ext}'
            cover_url = s3_upload(cover_bytes, cover_key, cover_file.content_type or 'image/jpeg')

            # Upload audio
            audio_bytes = audio_file.read()
            audio_ext = (audio_file.filename or 'audio.mp3').rsplit('.', 1)[-1].lower()
            audio_key = f'audio/{song_id_tmp}.{audio_ext}'
            audio_url = s3_upload(audio_bytes, audio_key, audio_file.content_type or 'audio/mpeg')

            print(f'[UPLOAD] cover_url={cover_url} audio_url={audio_url}', flush=True)

            if not cover_url or not audio_url:
                error = 'Ошибка загрузки файлов в хранилище. Проверь логи Railway.'
            else:
                song = Song(
                    title=title,
                    artist=artist,
                    cover_file_id=cover_url,   # storing URL instead of TG file_id
                    audio_file_id=audio_url,
                    uploaded_by=user.id,
                    status='pending'
                )
                db.session.add(song)
                db.session.flush()

                review_text = (
                    f'🎵 <b>Новый трек на модерации</b>\n\n'
                    f'Название: <b>{title}</b>\n'
                    f'Артист: <b>{artist}</b>\n'
                    f'От: @{user.telegram_username or user.telegram_first_name or "?"}\n\n'
                    f'Обложка: {cover_url}\n'
                    f'Аудио: {audio_url}'
                )
                markup = {
                    'inline_keyboard': [[
                        {'text': '✅ Принять', 'callback_data': f'approve:{song.id}'},
                        {'text': '❌ Отклонить', 'callback_data': f'reject:{song.id}'},
                    ]]
                }
                first_msg_id = None
                for admin_id in ADMIN_IDS:
                    res = tg('sendMessage',
                        chat_id=admin_id,
                        text=review_text,
                        parse_mode='HTML',
                        reply_markup=markup
                    )
                    if res.get('ok') and first_msg_id is None:
                        first_msg_id = res['result']['message_id']

                if first_msg_id:
                    song.review_message_id = first_msg_id
                db.session.commit()
                success = 'Трек отправлен на проверку! 🎉'

    return render_template('upload.html', user=user, error=error, success=success,
                           is_admin=is_admin_user(user))

@app.route('/admin')
@admin_required
def admin():
    user = get_current_user()
    pending  = Song.query.filter_by(status='pending').order_by(Song.created_at.desc()).all()
    approved = Song.query.filter_by(status='approved').order_by(Song.created_at.desc()).all()
    rejected = Song.query.filter_by(status='rejected').order_by(Song.created_at.desc()).all()
    return render_template('admin.html', user=user, pending=pending,
                           approved=approved, rejected=rejected, is_admin=True)

# ─────────────────────────── API ───────────────────────────────────────────

@app.route('/api/tg-auth', methods=['POST'])
def tg_auth():
    data = request.get_json(force=True)
    init_data = data.get('initData', '')

    if session.get('user_id'):
        return jsonify({'ok': True, 'already_logged_in': True})

    if not init_data:
        return jsonify({'error': 'no_init_data'}), 400

    valid, tg_user = verify_tg_webapp(init_data)
    if not valid:
        return jsonify({'error': 'invalid_data'}), 401

    tg_id = tg_user.get('id')
    if not tg_id:
        return jsonify({'error': 'no_user_id'}), 400

    user = User.query.filter_by(telegram_id=tg_id).first()
    if not user:
        user = User(
            telegram_id=tg_id,
            telegram_username=tg_user.get('username'),
            telegram_first_name=tg_user.get('first_name'),
        )
        db.session.add(user)
        db.session.commit()

    session.permanent = True
    session['user_id'] = user.id
    return jsonify({'ok': True, 'already_logged_in': False, 'token': user.token, 'user': user.to_dict()})

@app.route('/api/tg-login')
def tg_login():
    token = request.args.get('token', '').strip()
    if not token:
        return redirect(url_for('login'))
    user = User.query.filter_by(token=token).first()
    if not user:
        return redirect(url_for('login'))
    session.permanent = True
    session['user_id'] = user.id
    return redirect(url_for('index'))

@app.route('/api/songs')
def api_songs():
    songs = Song.query.filter_by(status='approved').order_by(Song.created_at.desc()).all()
    result = []
    for s in songs:
        d = s.to_dict()
        d['cover_url'] = url_for('serve_cover', song_id=s.id)
        d['audio_url'] = url_for('stream_audio', song_id=s.id)
        result.append(d)
    return jsonify(result)

@app.route('/api/admin/action', methods=['POST'])
@admin_required
def admin_action():
    data = request.get_json(force=True)
    song_id = data.get('song_id')
    action  = data.get('action')
    song = db.session.get(Song, song_id)
    if not song:
        return jsonify({'error': 'not found'}), 404
    if action == 'approve':
        song.status = 'approved'
        notify_admins(f'✅ Принято: <b>{song.title}</b> — {song.artist}')
    elif action == 'reject':
        song.status = 'rejected'
        notify_admins(f'❌ Отклонено: <b>{song.title}</b> — {song.artist}')
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/debug-s3')
def debug_s3():
    """Quick check that S3 vars are loaded correctly."""
    return jsonify({
        'endpoint': S3_ENDPOINT,
        'bucket': S3_BUCKET,
        'region': S3_REGION,
        'key_set': bool(S3_ACCESS_KEY),
        'secret_set': bool(S3_SECRET_KEY),
    })

# ─────────────────────────── File serving ──────────────────────────────────

@app.route('/cover/<int:song_id>')
def serve_cover(song_id):
    song = db.session.get(Song, song_id)
    if not song or not song.cover_file_id:
        abort(404)
    # cover_file_id is now a direct S3 URL
    return redirect(song.cover_file_id)

@app.route('/stream/<int:song_id>')
def stream_audio(song_id):
    song = db.session.get(Song, song_id)
    if not song or song.status != 'approved' or not song.audio_file_id:
        abort(404)

    # audio_file_id is now a direct S3 URL
    audio_url = song.audio_file_id

    range_header = request.headers.get('Range')
    req_headers = {}
    if range_header:
        req_headers['Range'] = range_header

    try:
        s3_resp = requests.get(audio_url, headers=req_headers, stream=True, timeout=10)
    except Exception as e:
        print(f'[STREAM] error: {e}', flush=True)
        abort(500)

    headers = {
        'Content-Type': s3_resp.headers.get('Content-Type', 'audio/mpeg'),
        'Accept-Ranges': 'bytes',
        'Access-Control-Allow-Origin': '*',
    }
    if 'Content-Length' in s3_resp.headers:
        headers['Content-Length'] = s3_resp.headers['Content-Length']
    if 'Content-Range' in s3_resp.headers:
        headers['Content-Range'] = s3_resp.headers['Content-Range']

    return Response(
        stream_with_context(s3_resp.iter_content(chunk_size=65536)),
        status=s3_resp.status_code,
        headers=headers,
    )

# ─────────────────────────── Telegram Webhook ──────────────────────────────

@app.route(f'/webhook/{WEBHOOK_SECRET}', methods=['POST'])
def telegram_webhook():
    data = request.get_json(force=True)

    msg = data.get('message', {})
    if msg:
        chat_id    = msg['chat']['id']
        text       = msg.get('text', '')
        from_user  = msg.get('from', {})
        tg_id      = from_user.get('id')

        if text.startswith('/start') and tg_id:
            user = User.query.filter_by(telegram_id=tg_id).first()
            if not user:
                user = User(
                    telegram_id=tg_id,
                    telegram_username=from_user.get('username'),
                    telegram_first_name=from_user.get('first_name'),
                )
                db.session.add(user)
                db.session.commit()
                greeting = '👋 Добро пожаловать в <b>HertMusic</b>!\n\n'
            else:
                greeting = '🎵 С возвращением в <b>HertMusic</b>!\n\n'

            tg('sendMessage',
               chat_id=chat_id,
               text=(
                   f'{greeting}'
                   f'Твой токен для входа на сайт:\n\n'
                   f'<code>{user.token}</code>\n\n'
                   f'Введи его на странице входа 👆'
               ),
               parse_mode='HTML')

    cb = data.get('callback_query', {})
    if cb:
        callback_id   = cb['id']
        cb_data       = cb.get('data', '')
        from_user     = cb.get('from', {})
        cb_from_id    = str(from_user.get('id', ''))
        cb_from_uname = (from_user.get('username') or '').lower()
        caller_is_admin = (cb_from_id in ADMIN_IDS) or (cb_from_uname in ADMIN_USERNAMES)

        if not caller_is_admin:
            tg('answerCallbackQuery', callback_query_id=callback_id, text='⛔ Нет доступа')
            return 'ok'

        if ':' in cb_data:
            action, song_id_str = cb_data.split(':', 1)
            song = db.session.get(Song, int(song_id_str))
            if song:
                if action == 'approve':
                    song.status = 'approved'
                    answer = f'✅ Принято: {song.title}'
                elif action == 'reject':
                    song.status = 'rejected'
                    answer = f'❌ Отклонено: {song.title}'
                else:
                    answer = 'Неизвестное действие'
                db.session.commit()
                tg('answerCallbackQuery', callback_query_id=callback_id, text=answer)
                msg_id = cb.get('message', {}).get('message_id')
                if msg_id:
                    tg('editMessageReplyMarkup',
                       chat_id=cb_from_id,
                       message_id=msg_id,
                       reply_markup={'inline_keyboard': []})
                notify_admins(answer)
            else:
                tg('answerCallbackQuery', callback_query_id=callback_id, text='Трек не найден')

    return 'ok'

@app.route('/setup-webhook')
def setup_webhook():
    base_url = request.host_url.rstrip('/').replace('http://', 'https://')
    webhook_url = f'{base_url}/webhook/{WEBHOOK_SECRET}'
    return jsonify({'webhook_url': webhook_url, 'result': tg('setWebhook', url=webhook_url)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
from flask import (
Flask, render_template, request, jsonify,
session, redirect, url_for, abort, Response, stream_with_context
)
from models import db, User, Song

app = Flask(**name**)
app.secret_key = os.environ.get(‘SECRET_KEY’, secrets.token_hex(32))
app.config[‘PERMANENT_SESSION_LIFETIME’] = timedelta(days=90)
app.config[‘SESSION_COOKIE_SAMESITE’] = ‘None’
app.config[‘SESSION_COOKIE_SECURE’] = True

DATABASE_URL = os.environ.get(‘DATABASE_URL’, ‘’)
if DATABASE_URL.startswith(‘postgres://’):
DATABASE_URL = DATABASE_URL.replace(‘postgres://’, ‘postgresql://’, 1)

app.config[‘SQLALCHEMY_DATABASE_URI’] = DATABASE_URL or ‘sqlite:///hertmusic.db’
app.config[‘SQLALCHEMY_TRACK_MODIFICATIONS’] = False
app.config[‘MAX_CONTENT_LENGTH’] = 200 * 1024 * 1024

BOT_TOKEN = os.environ.get(‘BOT_TOKEN’, ‘’)
WEBHOOK_SECRET = os.environ.get(‘WEBHOOK_SECRET’, secrets.token_hex(16))

_raw_ids = os.environ.get(‘ADMIN_TELEGRAM_IDS’, os.environ.get(‘ADMIN_TELEGRAM_ID’, ‘’))
ADMIN_IDS = {s.strip() for s in _raw_ids.split(’,’) if s.strip()}
ADMIN_USERNAMES = {‘zawarkayt’, ‘bread6942’}
_raw_unames = os.environ.get(‘ADMIN_USERNAMES’, ‘’)
if _raw_unames:
ADMIN_USERNAMES = {s.strip().lstrip(’@’).lower() for s in _raw_unames.split(’,’) if s.strip()}

# ─────────────────────────── S3 / Railway Bucket ───────────────────────────

# Railway AWS-style bucket variables

S3_ENDPOINT   = os.environ.get(‘AWS_ENDPOINT_URL_S3’) or os.environ.get(‘RAILWAY_BUCKET_ENDPOINT_URL’, ‘’)
S3_ACCESS_KEY = os.environ.get(‘AWS_ACCESS_KEY_ID’) or os.environ.get(‘RAILWAY_BUCKET_ACCESS_KEY_ID’, ‘’)
S3_SECRET_KEY = os.environ.get(‘AWS_SECRET_ACCESS_KEY’) or os.environ.get(‘RAILWAY_BUCKET_SECRET_ACCESS_KEY’, ‘’)
S3_REGION     = os.environ.get(‘AWS_REGION’) or os.environ.get(‘AWS_DEFAULT_REGION’) or os.environ.get(‘RAILWAY_BUCKET_REGION’, ‘auto’)
S3_BUCKET     = os.environ.get(‘BUCKET_NAME’) or os.environ.get(‘AWS_BUCKET_NAME’) or os.environ.get(‘RAILWAY_BUCKET_NAME’, ‘’)

def get_s3():
return boto3.client(
‘s3’,
endpoint_url=S3_ENDPOINT,
aws_access_key_id=S3_ACCESS_KEY,
aws_secret_access_key=S3_SECRET_KEY,
region_name=S3_REGION,
config=Config(signature_version=‘s3v4’)
)

def s3_upload(file_bytes: bytes, key: str, content_type: str) -> str | None:
“”“Upload bytes to S3, return public URL or None on error.”””
try:
s3 = get_s3()
s3.put_object(
Bucket=S3_BUCKET,
Key=key,
Body=file_bytes,
ContentType=content_type,
)
# Build public URL
url = f’{S3_ENDPOINT.rstrip(”/”)}/{S3_BUCKET}/{key}’
print(f’[S3] uploaded {key} → {url}’, flush=True)
return url
except Exception as e:
print(f’[S3] upload error: {e}’, flush=True)
return None

def s3_presign(key: str, expires: int = 3600) -> str | None:
“”“Generate presigned URL for private object.”””
try:
s3 = get_s3()
url = s3.generate_presigned_url(
‘get_object’,
Params={‘Bucket’: S3_BUCKET, ‘Key’: key},
ExpiresIn=expires
)
return url
except Exception as e:
print(f’[S3] presign error: {e}’, flush=True)
return None

def s3_delete(key: str):
try:
s3 = get_s3()
s3.delete_object(Bucket=S3_BUCKET, Key=key)
except Exception as e:
print(f’[S3] delete error: {e}’, flush=True)

db.init_app(app)
with app.app_context():
db.create_all()

# ─────────────────────────── Telegram helpers ──────────────────────────────

def tg(method, **kwargs):
url = f’https://api.telegram.org/bot{BOT_TOKEN}/{method}’
try:
r = requests.post(url, json=kwargs, timeout=15)
return r.json()
except Exception as e:
print(f’[TG] {method} error: {e}’, flush=True)
return {}

def notify_admins(text, reply_markup=None):
for admin_id in ADMIN_IDS:
kwargs = dict(chat_id=admin_id, text=text, parse_mode=‘HTML’)
if reply_markup:
kwargs[‘reply_markup’] = reply_markup
tg(‘sendMessage’, **kwargs)

# ─────────────────────────── Auth helpers ──────────────────────────────────

def verify_tg_webapp(init_data_raw: str):
if not BOT_TOKEN:
return True, {}
try:
parsed = dict(
pair.split(’=’, 1)
for pair in unquote(init_data_raw).split(’&’)
if ‘=’ in pair
)
received_hash = parsed.pop(‘hash’, ‘’)
data_check = ‘\n’.join(f’{k}={v}’ for k, v in sorted(parsed.items()))
secret_key = hmac.new(b’WebAppData’, BOT_TOKEN.encode(), hashlib.sha256).digest()
computed = hmac.new(secret_key, data_check.encode(), hashlib.sha256).hexdigest()
valid = hmac.compare_digest(computed, received_hash)
user_data = json.loads(parsed.get(‘user’, ‘{}’))
return valid, user_data
except Exception as e:
print(f’[Auth] verify error: {e}’, flush=True)
return False, {}

def is_admin_user(user) -> bool:
if not user:
return False
if str(user.telegram_id) in ADMIN_IDS:
return True
uname = (user.telegram_username or ‘’).lower().lstrip(’@’)
return uname in ADMIN_USERNAMES

def login_required(f):
@wraps(f)
def decorated(*args, **kwargs):
if ‘user_id’ not in session:
if request.is_json:
return jsonify({‘error’: ‘unauthorized’}), 401
return redirect(url_for(‘login’))
return f(*args, **kwargs)
return decorated

def admin_required(f):
@wraps(f)
def decorated(*args, **kwargs):
if ‘user_id’ not in session:
return redirect(url_for(‘login’))
user = db.session.get(User, session[‘user_id’])
if not is_admin_user(user):
abort(403)
return f(*args, **kwargs)
return decorated

def get_current_user():
uid = session.get(‘user_id’)
return db.session.get(User, uid) if uid else None

# ─────────────────────────── Pages ─────────────────────────────────────────

@app.route(’/’)
def index():
user = get_current_user()
songs = Song.query.filter_by(status=‘approved’).order_by(Song.created_at.desc()).all()
return render_template(‘index.html’, user=user, songs=songs, is_admin=is_admin_user(user))

@app.route(’/login’, methods=[‘GET’, ‘POST’])
def login():
if get_current_user():
return redirect(url_for(‘index’))
error = None
if request.method == ‘POST’:
token = request.form.get(‘token’, ‘’).strip()
user = User.query.filter_by(token=token).first()
if user:
session.permanent = True
session[‘user_id’] = user.id
return redirect(url_for(‘index’))
error = ‘Неверный токен’
return render_template(‘login.html’, error=error)

@app.route(’/logout’)
def logout():
session.clear()
return redirect(url_for(‘index’))

@app.route(’/upload’, methods=[‘GET’, ‘POST’])
@login_required
def upload():
user = get_current_user()
error = None
success = None

```
if request.method == 'POST':
    title  = request.form.get('title', '').strip()
    artist = request.form.get('artist', '').strip()
    cover_file = request.files.get('cover')
    audio_file = request.files.get('audio')

    print(f'[UPLOAD] title={repr(title)} artist={repr(artist)} cover={getattr(cover_file,"filename",None)} audio={getattr(audio_file,"filename",None)}', flush=True)
    print(f'[S3] bucket={S3_BUCKET} endpoint={S3_ENDPOINT}', flush=True)

    if not all([title, artist, cover_file, audio_file]):
        error = 'Заполни все поля'
    elif not S3_BUCKET or not S3_ENDPOINT:
        error = 'S3 bucket не настроен. Проверь переменные в Railway.'
    else:
        song_id_tmp = secrets.token_hex(8)

        # Upload cover
        cover_bytes = cover_file.read()
        cover_ext = (cover_file.filename or 'cover.jpg').rsplit('.', 1)[-1].lower()
        cover_key = f'covers/{song_id_tmp}.{cover_ext}'
        cover_url = s3_upload(cover_bytes, cover_key, cover_file.content_type or 'image/jpeg')

        # Upload audio
        audio_bytes = audio_file.read()
        audio_ext = (audio_file.filename or 'audio.mp3').rsplit('.', 1)[-1].lower()
        audio_key = f'audio/{song_id_tmp}.{audio_ext}'
        audio_url = s3_upload(audio_bytes, audio_key, audio_file.content_type or 'audio/mpeg')

        print(f'[UPLOAD] cover_url={cover_url} audio_url={audio_url}', flush=True)

        if not cover_url or not audio_url:
            error = 'Ошибка загрузки файлов в хранилище. Проверь логи Railway.'
        else:
            song = Song(
                title=title,
                artist=artist,
                cover_file_id=cover_url,   # storing URL instead of TG file_id
                audio_file_id=audio_url,
                uploaded_by=user.id,
                status='pending'
            )
            db.session.add(song)
            db.session.flush()

            review_text = (
                f'🎵 <b>Новый трек на модерации</b>\n\n'
                f'Название: <b>{title}</b>\n'
                f'Артист: <b>{artist}</b>\n'
                f'От: @{user.telegram_username or user.telegram_first_name or "?"}\n\n'
                f'Обложка: {cover_url}\n'
                f'Аудио: {audio_url}'
            )
            markup = {
                'inline_keyboard': [[
                    {'text': '✅ Принять', 'callback_data': f'approve:{song.id}'},
                    {'text': '❌ Отклонить', 'callback_data': f'reject:{song.id}'},
                ]]
            }
            first_msg_id = None
            for admin_id in ADMIN_IDS:
                res = tg('sendMessage',
                    chat_id=admin_id,
                    text=review_text,
                    parse_mode='HTML',
                    reply_markup=markup
                )
                if res.get('ok') and first_msg_id is None:
                    first_msg_id = res['result']['message_id']

            if first_msg_id:
                song.review_message_id = first_msg_id
            db.session.commit()
            success = 'Трек отправлен на проверку! 🎉'

return render_template('upload.html', user=user, error=error, success=success,
                       is_admin=is_admin_user(user))
```

@app.route(’/admin’)
@admin_required
def admin():
user = get_current_user()
pending  = Song.query.filter_by(status=‘pending’).order_by(Song.created_at.desc()).all()
approved = Song.query.filter_by(status=‘approved’).order_by(Song.created_at.desc()).all()
rejected = Song.query.filter_by(status=‘rejected’).order_by(Song.created_at.desc()).all()
return render_template(‘admin.html’, user=user, pending=pending,
approved=approved, rejected=rejected, is_admin=True)

# ─────────────────────────── API ───────────────────────────────────────────

@app.route(’/api/tg-auth’, methods=[‘POST’])
def tg_auth():
data = request.get_json(force=True)
init_data = data.get(‘initData’, ‘’)

```
if session.get('user_id'):
    return jsonify({'ok': True, 'already_logged_in': True})

if not init_data:
    return jsonify({'error': 'no_init_data'}), 400

valid, tg_user = verify_tg_webapp(init_data)
if not valid:
    return jsonify({'error': 'invalid_data'}), 401

tg_id = tg_user.get('id')
if not tg_id:
    return jsonify({'error': 'no_user_id'}), 400

user = User.query.filter_by(telegram_id=tg_id).first()
if not user:
    user = User(
        telegram_id=tg_id,
        telegram_username=tg_user.get('username'),
        telegram_first_name=tg_user.get('first_name'),
    )
    db.session.add(user)
    db.session.commit()

session.permanent = True
session['user_id'] = user.id
return jsonify({'ok': True, 'already_logged_in': False, 'token': user.token, 'user': user.to_dict()})
```

@app.route(’/api/tg-login’)
def tg_login():
token = request.args.get(‘token’, ‘’).strip()
if not token:
return redirect(url_for(‘login’))
user = User.query.filter_by(token=token).first()
if not user:
return redirect(url_for(‘login’))
session.permanent = True
session[‘user_id’] = user.id
return redirect(url_for(‘index’))

@app.route(’/api/songs’)
def api_songs():
songs = Song.query.filter_by(status=‘approved’).order_by(Song.created_at.desc()).all()
result = []
for s in songs:
d = s.to_dict()
d[‘cover_url’] = url_for(‘serve_cover’, song_id=s.id)
d[‘audio_url’] = url_for(‘stream_audio’, song_id=s.id)
result.append(d)
return jsonify(result)

@app.route(’/api/admin/action’, methods=[‘POST’])
@admin_required
def admin_action():
data = request.get_json(force=True)
song_id = data.get(‘song_id’)
action  = data.get(‘action’)
song = db.session.get(Song, song_id)
if not song:
return jsonify({‘error’: ‘not found’}), 404
if action == ‘approve’:
song.status = ‘approved’
notify_admins(f’✅ Принято: <b>{song.title}</b> — {song.artist}’)
elif action == ‘reject’:
song.status = ‘rejected’
notify_admins(f’❌ Отклонено: <b>{song.title}</b> — {song.artist}’)
db.session.commit()
return jsonify({‘ok’: True})

@app.route(’/api/debug-s3’)
def debug_s3():
“”“Quick check that S3 vars are loaded correctly.”””
return jsonify({
‘endpoint’: S3_ENDPOINT,
‘bucket’: S3_BUCKET,
‘region’: S3_REGION,
‘key_set’: bool(S3_ACCESS_KEY),
‘secret_set’: bool(S3_SECRET_KEY),
})

# ─────────────────────────── File serving ──────────────────────────────────

@app.route(’/cover/<int:song_id>’)
def serve_cover(song_id):
song = db.session.get(Song, song_id)
if not song or not song.cover_file_id:
abort(404)
# cover_file_id is now a direct S3 URL
return redirect(song.cover_file_id)

@app.route(’/stream/<int:song_id>’)
def stream_audio(song_id):
song = db.session.get(Song, song_id)
if not song or song.status != ‘approved’ or not song.audio_file_id:
abort(404)

```
# audio_file_id is now a direct S3 URL
audio_url = song.audio_file_id

range_header = request.headers.get('Range')
req_headers = {}
if range_header:
    req_headers['Range'] = range_header

try:
    s3_resp = requests.get(audio_url, headers=req_headers, stream=True, timeout=10)
except Exception as e:
    print(f'[STREAM] error: {e}', flush=True)
    abort(500)

headers = {
    'Content-Type': s3_resp.headers.get('Content-Type', 'audio/mpeg'),
    'Accept-Ranges': 'bytes',
    'Access-Control-Allow-Origin': '*',
}
if 'Content-Length' in s3_resp.headers:
    headers['Content-Length'] = s3_resp.headers['Content-Length']
if 'Content-Range' in s3_resp.headers:
    headers['Content-Range'] = s3_resp.headers['Content-Range']

return Response(
    stream_with_context(s3_resp.iter_content(chunk_size=65536)),
    status=s3_resp.status_code,
    headers=headers,
)
```

# ─────────────────────────── Telegram Webhook ──────────────────────────────

@app.route(f’/webhook/{WEBHOOK_SECRET}’, methods=[‘POST’])
def telegram_webhook():
data = request.get_json(force=True)

```
msg = data.get('message', {})
if msg:
    chat_id    = msg['chat']['id']
    text       = msg.get('text', '')
    from_user  = msg.get('from', {})
    tg_id      = from_user.get('id')

    if text.startswith('/start') and tg_id:
        user = User.query.filter_by(telegram_id=tg_id).first()
        if not user:
            user = User(
                telegram_id=tg_id,
                telegram_username=from_user.get('username'),
                telegram_first_name=from_user.get('first_name'),
            )
            db.session.add(user)
            db.session.commit()
            greeting = '👋 Добро пожаловать в <b>HertMusic</b>!\n\n'
        else:
            greeting = '🎵 С возвращением в <b>HertMusic</b>!\n\n'

        tg('sendMessage',
           chat_id=chat_id,
           text=(
               f'{greeting}'
               f'Твой токен для входа на сайт:\n\n'
               f'<code>{user.token}</code>\n\n'
               f'Введи его на странице входа 👆'
           ),
           parse_mode='HTML')

cb = data.get('callback_query', {})
if cb:
    callback_id   = cb['id']
    cb_data       = cb.get('data', '')
    from_user     = cb.get('from', {})
    cb_from_id    = str(from_user.get('id', ''))
    cb_from_uname = (from_user.get('username') or '').lower()
    caller_is_admin = (cb_from_id in ADMIN_IDS) or (cb_from_uname in ADMIN_USERNAMES)

    if not caller_is_admin:
        tg('answerCallbackQuery', callback_query_id=callback_id, text='⛔ Нет доступа')
        return 'ok'

    if ':' in cb_data:
        action, song_id_str = cb_data.split(':', 1)
        song = db.session.get(Song, int(song_id_str))
        if song:
            if action == 'approve':
                song.status = 'approved'
                answer = f'✅ Принято: {song.title}'
            elif action == 'reject':
                song.status = 'rejected'
                answer = f'❌ Отклонено: {song.title}'
            else:
                answer = 'Неизвестное действие'
            db.session.commit()
            tg('answerCallbackQuery', callback_query_id=callback_id, text=answer)
            msg_id = cb.get('message', {}).get('message_id')
            if msg_id:
                tg('editMessageReplyMarkup',
                   chat_id=cb_from_id,
                   message_id=msg_id,
                   reply_markup={'inline_keyboard': []})
            notify_admins(answer)
        else:
            tg('answerCallbackQuery', callback_query_id=callback_id, text='Трек не найден')

return 'ok'
```

@app.route(’/setup-webhook’)
def setup_webhook():
base_url = request.host_url.rstrip(’/’).replace(‘http://’, ‘https://’)
webhook_url = f’{base_url}/webhook/{WEBHOOK_SECRET}’
return jsonify({‘webhook_url’: webhook_url, ‘result’: tg(‘setWebhook’, url=webhook_url)})

if **name** == ‘**main**’:
app.run(host=‘0.0.0.0’, port=int(os.environ.get(‘PORT’, 5000)), debug=False)
