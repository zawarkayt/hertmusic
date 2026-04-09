import os
import json
import hmac
import hashlib
import secrets
import requests
from functools import wraps
from urllib.parse import parse_qs, unquote

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, abort, Response, stream_with_context
)
from models import db, User, Song

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DATABASE_URL = os.environ.get('DATABASE_URL', '')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///hertmusic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 150 * 1024 * 1024

BOT_TOKEN = os.environ.get('BOT_TOKEN', '')
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', secrets.token_hex(16))

# Multiple admins: ADMIN_TELEGRAM_IDS=123456,789012  (Telegram numeric IDs)
# ADMIN_USERNAMES=zawarkayt,bread6942  (fallback, без @)
_raw_ids = os.environ.get('ADMIN_TELEGRAM_IDS', os.environ.get('ADMIN_TELEGRAM_ID', ''))
ADMIN_IDS = {s.strip() for s in _raw_ids.split(',') if s.strip()}
ADMIN_USERNAMES = {'zawarkayt', 'bread6942'}  # hardcoded + env override
_raw_unames = os.environ.get('ADMIN_USERNAMES', '')
if _raw_unames:
    ADMIN_USERNAMES = {s.strip().lstrip('@').lower() for s in _raw_unames.split(',') if s.strip()}

def is_admin_user(user: 'User') -> bool:
    """Check if a User model instance is an admin."""
    if not user:
        return False
    if str(user.telegram_id) in ADMIN_IDS:
        return True
    uname = (user.telegram_username or '').lower().lstrip('@')
    return uname in ADMIN_USERNAMES

def is_admin_tg_id(tg_id) -> bool:
    """Check by raw Telegram ID (int or str)."""
    return str(tg_id) in ADMIN_IDS

def notify_admins(text, reply_markup=None):
    """Send a message to all known admin IDs."""
    for admin_id in ADMIN_IDS:
        kwargs = dict(chat_id=admin_id, text=text, parse_mode='HTML')
        if reply_markup:
            kwargs['reply_markup'] = reply_markup
        tg('sendMessage', **kwargs)

db.init_app(app)

with app.app_context():
    db.create_all()


# ─────────────────────────── Telegram helpers ────────────────────────────── #

def tg(method, **kwargs):
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/{method}'
    try:
        r = requests.post(url, json=kwargs, timeout=15)
        return r.json()
    except Exception as e:
        print(f'[TG] {method} error: {e}')
        return {}

def tg_send_file(chat_id, file_bytes, filename, file_type='document', caption=''):
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/send{file_type.capitalize()}'
    files_key = 'photo' if file_type == 'photo' else 'document'
    try:
        r = requests.post(url, data={'chat_id': chat_id, 'caption': caption}, 
                          files={files_key: (filename, file_bytes)}, timeout=60)
        return r.json()
    except Exception as e:
        print(f'[TG] send_file error: {e}')
        return {}

def tg_get_file_url(file_id):
    res = tg('getFile', file_id=file_id)
    if res.get('ok'):
        path = res['result']['file_path']
        return f'https://api.telegram.org/file/bot{BOT_TOKEN}/{path}'
    return None


# ─────────────────────────── Auth helpers ────────────────────────────────── #

def verify_tg_webapp(init_data_raw: str) -> tuple[bool, dict]:
    """Verify Telegram WebApp initData signature."""
    try:
        parsed = dict(pair.split('=', 1) for pair in unquote(init_data_raw).split('&') if '=' in pair)
        received_hash = parsed.pop('hash', '')
        data_check = '\n'.join(f'{k}={v}' for k, v in sorted(parsed.items()))
        secret_key = hmac.new(b'WebAppData', BOT_TOKEN.encode(), hashlib.sha256).digest()
        computed = hmac.new(secret_key, data_check.encode(), hashlib.sha256).hexdigest()
        valid = hmac.compare_digest(computed, received_hash)
        user_data = json.loads(parsed.get('user', '{}'))
        return valid, user_data
    except Exception as e:
        print(f'[Auth] verify error: {e}')
        return False, {}

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
        user = User.query.get(session['user_id'])
        if not is_admin_user(user):
            abort(403)
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    uid = session.get('user_id')
    return User.query.get(uid) if uid else None


# ─────────────────────────── Pages ───────────────────────────────────────── #

@app.route('/')
def index():
    user = get_current_user()
    songs = Song.query.filter_by(status='approved').order_by(Song.created_at.desc()).all()
    is_admin = is_admin_user(user)
    return render_template('index.html', user=user, songs=songs, is_admin=is_admin)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if get_current_user():
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        user = User.query.filter_by(token=token).first()
        if user:
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
        title = request.form.get('title', '').strip()
        artist = request.form.get('artist', '').strip()
        cover_file = request.files.get('cover')
        audio_file = request.files.get('audio')

        if not all([title, artist, cover_file, audio_file]):
            error = 'Заполни все поля'
        else:
            # Pick one admin to store files (first in set, or use a dedicated storage channel)
            storage_chat = next(iter(ADMIN_IDS), None) if ADMIN_IDS else None
            if not storage_chat:
                error = 'Нет настроенных администраторов'
            else:
                # Send cover to Telegram for storage
                cover_bytes = cover_file.read()
                cover_res = tg_send_file(
                    storage_chat, cover_bytes, cover_file.filename,
                    file_type='photo',
                    caption=f'🖼 Обложка: {title} — {artist}'
                )
                cover_file_id = None
                if cover_res.get('ok'):
                    photos = cover_res['result'].get('photo', [])
                    if photos:
                        cover_file_id = photos[-1]['file_id']

                # Send audio to Telegram for storage
                audio_bytes = audio_file.read()
                audio_res = tg_send_file(
                    storage_chat, audio_bytes, audio_file.filename,
                    file_type='document',
                    caption=f'🎧 Аудио: {title} — {artist}'
                )
                audio_file_id = None
                if audio_res.get('ok'):
                    audio_file_id = audio_res['result'].get('document', {}).get('file_id')

            if not storage_chat:
                pass  # error already set
            elif not cover_file_id or not audio_file_id:
                error = 'Ошибка при загрузке файлов на Telegram'
            else:
                # Send review message to admin
                review_text = (
                    f'🎵 <b>Новая песня на модерации</b>\n\n'
                    f'Название: <b>{title}</b>\n'
                    f'Артист: <b>{artist}</b>\n'
                    f'От: @{user.telegram_username or user.telegram_first_name}'
                )
                song = Song(
                    title=title,
                    artist=artist,
                    cover_file_id=cover_file_id,
                    audio_file_id=audio_file_id,
                    uploaded_by=user.id,
                    status='pending'
                )
                db.session.add(song)
                db.session.flush()

                markup = {
                    'inline_keyboard': [[
                        {'text': '✅ Принять', 'callback_data': f'approve:{song.id}'},
                        {'text': '❌ Отклонить', 'callback_data': f'reject:{song.id}'},
                    ]]
                }
                # Notify all admins
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
                success = 'Трек отправлен на проверку!'

    is_admin = is_admin_user(user)
    return render_template('upload.html', user=user, error=error, success=success, is_admin=is_admin)

@app.route('/admin')
@admin_required
def admin():
    user = get_current_user()
    pending = Song.query.filter_by(status='pending').order_by(Song.created_at.desc()).all()
    approved = Song.query.filter_by(status='approved').order_by(Song.created_at.desc()).all()
    rejected = Song.query.filter_by(status='rejected').order_by(Song.created_at.desc()).all()
    return render_template('admin.html', user=user, pending=pending,
                           approved=approved, rejected=rejected, is_admin=True)


# ─────────────────────────── API ─────────────────────────────────────────── #

@app.route('/api/tg-auth', methods=['POST'])
def tg_auth():
    data = request.get_json(force=True)
    init_data = data.get('initData', '')
    valid, tg_user = verify_tg_webapp(init_data)
    if not valid and BOT_TOKEN:
        return jsonify({'error': 'invalid_data'}), 401

    tg_id = tg_user.get('id')
    if not tg_id:
        return jsonify({'error': 'no_user_id'}), 400

    # Уже залогинен — ничего не делаем
    if session.get('user_id'):
        return jsonify({'ok': True, 'already_logged_in': True})

    user = User.query.filter_by(telegram_id=tg_id).first()
    if not user:
        user = User(
            telegram_id=tg_id,
            telegram_username=tg_user.get('username'),
            telegram_first_name=tg_user.get('first_name'),
        )
        db.session.add(user)
        db.session.commit()

    session['user_id'] = user.id
    session.permanent = True
    return jsonify({'ok': True, 'already_logged_in': False, 'user': user.to_dict()})


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
    action = data.get('action')
    song = Song.query.get_or_404(song_id)
    if action == 'approve':
        song.status = 'approved'
        notify_admins(f'✅ Принято: <b>{song.title}</b> — {song.artist}')
    elif action == 'reject':
        song.status = 'rejected'
        notify_admins(f'❌ Отклонено: <b>{song.title}</b> — {song.artist}')
    db.session.commit()
    return jsonify({'ok': True})


# ─────────────────────────── File serving ────────────────────────────────── #

@app.route('/cover/<int:song_id>')
def serve_cover(song_id):
    song = Song.query.get_or_404(song_id)
    if not song.cover_file_id:
        abort(404)
    url = tg_get_file_url(song.cover_file_id)
    if not url:
        abort(404)
    return redirect(url)

@app.route('/stream/<int:song_id>')
def stream_audio(song_id):
    song = Song.query.get_or_404(song_id)
    if song.status != 'approved':
        abort(403)
    if not song.audio_file_id:
        abort(404)
    file_url = tg_get_file_url(song.audio_file_id)
    if not file_url:
        abort(404)

    range_header = request.headers.get('Range')
    req_headers = {}
    if range_header:
        req_headers['Range'] = range_header

    tg_resp = requests.get(file_url, headers=req_headers, stream=True, timeout=30)
    status = tg_resp.status_code

    headers = {
        'Content-Type': tg_resp.headers.get('Content-Type', 'audio/mpeg'),
        'Accept-Ranges': 'bytes',
        'Access-Control-Allow-Origin': '*',
    }
    if 'Content-Length' in tg_resp.headers:
        headers['Content-Length'] = tg_resp.headers['Content-Length']
    if 'Content-Range' in tg_resp.headers:
        headers['Content-Range'] = tg_resp.headers['Content-Range']

    return Response(
        stream_with_context(tg_resp.iter_content(chunk_size=65536)),
        status=status,
        headers=headers,
    )


# ─────────────────────────── Telegram webhook ────────────────────────────── #

@app.route(f'/webhook/{WEBHOOK_SECRET}', methods=['POST'])
def telegram_webhook():
    data = request.get_json(force=True)
    
    # Handle /start command
    msg = data.get('message', {})
    if msg:
        chat_id = msg['chat']['id']
        text = msg.get('text', '')
        from_user = msg.get('from', {})
        tg_id = from_user.get('id')

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
                greeting = 'Добро пожаловать в HertMusic! 🎵\n\n'
            else:
                greeting = 'С возвращением! 🎵\n\n'

            tg('sendMessage',
               chat_id=chat_id,
               text=(
                   f'{greeting}'
                   f'Твой токен для входа на сайт:\n\n'
                   f'<code>{user.token}</code>\n\n'
                   f'Скопируй и введи на hertmusic.up.railway.app'
               ),
               parse_mode='HTML')

    # Handle callback queries (approve/reject from admin)
    cb = data.get('callback_query', {})
    if cb:
        callback_id = cb['id']
        cb_data = cb.get('data', '')
        from_user = cb.get('from', {})

        cb_from_id = str(from_user.get('id', ''))
        cb_from_uname = (from_user.get('username') or '').lower()
        caller_is_admin = (cb_from_id in ADMIN_IDS) or (cb_from_uname in ADMIN_USERNAMES)
        if not caller_is_admin:
            tg('answerCallbackQuery', callback_query_id=callback_id, text='Нет доступа')
            return 'ok'

        if ':' in cb_data:
            action, song_id_str = cb_data.split(':', 1)
            song = Song.query.get(int(song_id_str))
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
                # Remove inline buttons from the message that was clicked
                msg_id = cb.get('message', {}).get('message_id')
                if msg_id:
                    tg('editMessageReplyMarkup',
                       chat_id=cb_from_id,
                       message_id=msg_id,
                       reply_markup={'inline_keyboard': []})
                # Notify all admins about the decision
                notify_admins(f'{answer}\n#moderation')
            else:
                tg('answerCallbackQuery', callback_query_id=callback_id, text='Трек не найден')

    return 'ok'


@app.route('/setup-webhook')
def setup_webhook():
    """Call once to register webhook. Protect this in production."""
    base_url = request.host_url.rstrip('/')
    webhook_url = f'{base_url}/webhook/{WEBHOOK_SECRET}'
    res = tg('setWebhook', url=webhook_url)
    return jsonify(res)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
