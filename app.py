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
from models import db, User, Song, Playlist, PlaylistSong

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=90)
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True

DATABASE_URL = os.environ.get("DATABASE_URL", "")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or "sqlite:///hertmusic.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", secrets.token_hex(16))

_raw_ids = os.environ.get("ADMIN_TELEGRAM_IDS", os.environ.get("ADMIN_TELEGRAM_ID", ""))
ADMIN_IDS = {s.strip() for s in _raw_ids.split(",") if s.strip()}
ADMIN_USERNAMES = {"zawarkayt", "bread6942"}
_raw_unames = os.environ.get("ADMIN_USERNAMES", "")
if _raw_unames:
    ADMIN_USERNAMES = {s.strip().lstrip("@").lower() for s in _raw_unames.split(",") if s.strip()}

# ─────────────────────────── S3 ──────────────────────────────────────────── #

S3_ENDPOINT   = os.environ.get("AWS_ENDPOINT_URL", "")
S3_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "")
S3_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
S3_REGION     = os.environ.get("AWS_DEFAULT_REGION", "auto")
S3_BUCKET     = os.environ.get("AWS_S3_BUCKET_NAME", "")

def get_s3():
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        region_name=S3_REGION,
        config=Config(signature_version="s3v4")
    )

def s3_upload(file_bytes: bytes, key: str, content_type: str):
    try:
        s3 = get_s3()
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=file_bytes,
            ContentType=content_type,
        )
        url = f"{S3_ENDPOINT.rstrip('/')}/{S3_BUCKET}/{key}"
        print(f"[S3] uploaded {key} -> {url}", flush=True)
        return url
    except Exception as e:
        print(f"[S3] upload error: {e}", flush=True)
        return None

def s3_presign(key: str, expires: int = 3600):
    try:
        s3 = get_s3()
        return s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": key},
            ExpiresIn=expires
        )
    except Exception as e:
        print(f"[S3] presign error: {e}", flush=True)
        return None

db.init_app(app)
with app.app_context():
    db.create_all()


# ─────────────────────────── Telegram ────────────────────────────────────── #

def tg(method, **kwargs):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    try:
        r = requests.post(url, json=kwargs, timeout=15)
        return r.json()
    except Exception as e:
        print(f"[TG] {method} error: {e}", flush=True)
        return {}

def notify_admins(text, reply_markup=None):
    for admin_id in ADMIN_IDS:
        kwargs = dict(chat_id=admin_id, text=text, parse_mode="HTML")
        if reply_markup:
            kwargs["reply_markup"] = reply_markup
        tg("sendMessage", **kwargs)


# ─────────────────────────── Auth ────────────────────────────────────────── #

def verify_tg_webapp(init_data_raw: str):
    if not BOT_TOKEN:
        return True, {}
    try:
        parsed = dict(
            pair.split("=", 1)
            for pair in unquote(init_data_raw).split("&")
            if "=" in pair
        )
        received_hash = parsed.pop("hash", "")
        data_check = "\n".join(f"{k}={v}" for k, v in sorted(parsed.items()))
        secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        computed = hmac.new(secret_key, data_check.encode(), hashlib.sha256).hexdigest()
        valid = hmac.compare_digest(computed, received_hash)
        user_data = json.loads(parsed.get("user", "{}"))
        return valid, user_data
    except Exception as e:
        print(f"[Auth] verify error: {e}", flush=True)
        return False, {}

def is_admin_user(user) -> bool:
    if not user:
        return False
    if str(user.telegram_id) in ADMIN_IDS:
        return True
    return (user.telegram_username or "").lower().lstrip("@") in ADMIN_USERNAMES

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json:
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        user = db.session.get(User, session["user_id"])
        if not is_admin_user(user):
            abort(403)
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None


# ─────────────────────────── Pages ───────────────────────────────────────── #

@app.route("/")
def index():
    user = get_current_user()
    songs = Song.query.filter_by(status="approved").order_by(Song.created_at.desc()).all()
    return render_template("index.html", user=user, songs=songs, is_admin=is_admin_user(user))

@app.route("/login", methods=["GET", "POST"])
def login():
    if get_current_user():
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        user = User.query.filter_by(token=token).first()
        if user:
            session.permanent = True
            session["user_id"] = user.id
            return redirect(url_for("index"))
        error = "Неверный токен"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    user = get_current_user()
    error = None
    success = None

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        artist = request.form.get("artist", "").strip()
        cover_file = request.files.get("cover")
        audio_file = request.files.get("audio")

        if not all([title, artist, cover_file, audio_file]):
            error = "Заполни все поля"
        elif not S3_BUCKET or not S3_ENDPOINT:
            error = "S3 bucket не настроен"
        else:
            uid = secrets.token_hex(8)
            cover_bytes = cover_file.read()
            cover_ext = (cover_file.filename or "cover.jpg").rsplit(".", 1)[-1].lower()
            cover_url = s3_upload(cover_bytes, f"covers/{uid}.{cover_ext}", cover_file.content_type or "image/jpeg")

            audio_bytes = audio_file.read()
            audio_ext = (audio_file.filename or "audio.mp3").rsplit(".", 1)[-1].lower()
            audio_url = s3_upload(audio_bytes, f"audio/{uid}.{audio_ext}", audio_file.content_type or "audio/mpeg")

            if not cover_url or not audio_url:
                error = "Ошибка загрузки файлов"
            else:
                song = Song(title=title, artist=artist,
                            cover_file_id=cover_url, audio_file_id=audio_url,
                            uploaded_by=user.id, status="pending")
                db.session.add(song)
                db.session.flush()

                markup = {"inline_keyboard": [[
                    {"text": "✅ Принять", "callback_data": f"approve:{song.id}"},
                    {"text": "❌ Отклонить", "callback_data": f"reject:{song.id}"},
                ]]}
                first_msg_id = None
                for admin_id in ADMIN_IDS:
                    res = tg("sendMessage", chat_id=admin_id, parse_mode="HTML", reply_markup=markup,
                             text=f"🎵 <b>Новый трек на модерации</b>\n\nНазвание: <b>{title}</b>\nАртист: <b>{artist}</b>\nОт: @{user.telegram_username or user.telegram_first_name or '?'}")
                    if res.get("ok") and first_msg_id is None:
                        first_msg_id = res["result"]["message_id"]
                if first_msg_id:
                    song.review_message_id = first_msg_id
                db.session.commit()
                success = "Трек отправлен на проверку! 🎉"

    return render_template("upload.html", user=user, error=error, success=success, is_admin=is_admin_user(user))

@app.route("/playlists")
@login_required
def playlists_page():
    user = get_current_user()
    my = Playlist.query.filter_by(owner_id=user.id).order_by(Playlist.created_at.desc()).all()
    public = Playlist.query.filter_by(is_public=True).order_by(Playlist.created_at.desc()).all()
    return render_template("playlists.html", user=user, my_playlists=my,
                           public_playlists=public, is_admin=is_admin_user(user))

@app.route("/playlists/<int:pl_id>")
@login_required
def playlist_detail(pl_id):
    user = get_current_user()
    pl = db.session.get(Playlist, pl_id)
    if not pl:
        abort(404)
    if not pl.is_public and pl.owner_id != user.id:
        abort(403)
    songs = Song.query.filter_by(status="approved").order_by(Song.created_at.desc()).all()
    return render_template("playlist_detail.html", user=user, playlist=pl,
                           all_songs=songs, is_admin=is_admin_user(user))

@app.route("/admin")
@admin_required
def admin():
    user = get_current_user()
    pending  = Song.query.filter_by(status="pending").order_by(Song.created_at.desc()).all()
    approved = Song.query.filter_by(status="approved").order_by(Song.created_at.desc()).all()
    rejected = Song.query.filter_by(status="rejected").order_by(Song.created_at.desc()).all()
    return render_template("admin.html", user=user, pending=pending,
                           approved=approved, rejected=rejected, is_admin=True)


# ─────────────────────────── API ─────────────────────────────────────────── #

@app.route("/api/tg-auth", methods=["POST"])
def tg_auth():
    data = request.get_json(force=True)
    init_data = data.get("initData", "")
    if session.get("user_id"):
        return jsonify({"ok": True, "already_logged_in": True})
    if not init_data:
        return jsonify({"error": "no_init_data"}), 400
    valid, tg_user = verify_tg_webapp(init_data)
    if not valid:
        return jsonify({"error": "invalid_data"}), 401
    tg_id = tg_user.get("id")
    if not tg_id:
        return jsonify({"error": "no_user_id"}), 400
    user = User.query.filter_by(telegram_id=tg_id).first()
    if not user:
        user = User(telegram_id=tg_id,
                    telegram_username=tg_user.get("username"),
                    telegram_first_name=tg_user.get("first_name"))
        db.session.add(user)
        db.session.commit()
    session.permanent = True
    session["user_id"] = user.id
    return jsonify({"ok": True, "already_logged_in": False, "token": user.token, "user": user.to_dict()})

@app.route("/api/tg-login")
def tg_login():
    token = request.args.get("token", "").strip()
    user = User.query.filter_by(token=token).first()
    if not user:
        return redirect(url_for("login"))
    session.permanent = True
    session["user_id"] = user.id
    return redirect(url_for("index"))

@app.route("/api/songs")
def api_songs():
    songs = Song.query.filter_by(status="approved").order_by(Song.created_at.desc()).all()
    result = []
    for s in songs:
        d = s.to_dict()
        d["cover_url"] = url_for("serve_cover", song_id=s.id)
        d["audio_url"] = url_for("stream_audio", song_id=s.id)
        result.append(d)
    return jsonify(result)

@app.route("/api/admin/action", methods=["POST"])
@admin_required
def admin_action():
    data = request.get_json(force=True)
    song = db.session.get(Song, data.get("song_id"))
    if not song:
        return jsonify({"error": "not found"}), 404
    action = data.get("action")
    if action == "approve":
        song.status = "approved"
        notify_admins(f"✅ Принято: <b>{song.title}</b> — {song.artist}")
    elif action == "reject":
        song.status = "rejected"
        notify_admins(f"❌ Отклонено: <b>{song.title}</b> — {song.artist}")
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/debug-s3")
def debug_s3():
    return jsonify({"endpoint": S3_ENDPOINT, "bucket": S3_BUCKET,
                    "region": S3_REGION, "key_set": bool(S3_ACCESS_KEY), "secret_set": bool(S3_SECRET_KEY)})

# ── Playlist API ─────────────────────────────────────────────────────────── #

@app.route("/api/playlists", methods=["GET"])
@login_required
def api_playlists():
    user = get_current_user()
    q = request.args.get("q", "").strip().lower()
    if q:
        results = Playlist.query.filter(
            Playlist.is_public == True,
            Playlist.name.ilike(f"%{q}%")
        ).order_by(Playlist.created_at.desc()).all()
    else:
        results = Playlist.query.filter_by(is_public=True).order_by(Playlist.created_at.desc()).all()
    return jsonify([p.to_dict() for p in results])

@app.route("/api/playlists", methods=["POST"])
@login_required
def api_create_playlist():
    user = get_current_user()
    data = request.get_json(force=True)
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    pl = Playlist(
        name=name,
        description=data.get("description", "").strip(),
        is_public=bool(data.get("is_public", True)),
        owner_id=user.id
    )
    db.session.add(pl)
    db.session.commit()
    return jsonify(pl.to_dict()), 201

@app.route("/api/playlists/<int:pl_id>", methods=["GET"])
@login_required
def api_playlist_detail(pl_id):
    user = get_current_user()
    pl = db.session.get(Playlist, pl_id)
    if not pl:
        return jsonify({"error": "not found"}), 404
    if not pl.is_public and pl.owner_id != user.id:
        return jsonify({"error": "forbidden"}), 403
    d = pl.to_dict(with_songs=True)
    for item in d["songs"]:
        item["cover_url"] = url_for("serve_cover", song_id=item["id"])
        item["audio_url"] = url_for("stream_audio", song_id=item["id"])
    return jsonify(d)

@app.route("/api/playlists/<int:pl_id>", methods=["DELETE"])
@login_required
def api_delete_playlist(pl_id):
    user = get_current_user()
    pl = db.session.get(Playlist, pl_id)
    if not pl:
        return jsonify({"error": "not found"}), 404
    if pl.owner_id != user.id and not is_admin_user(user):
        return jsonify({"error": "forbidden"}), 403
    db.session.delete(pl)
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/playlists/<int:pl_id>/songs", methods=["POST"])
@login_required
def api_playlist_add_song(pl_id):
    user = get_current_user()
    pl = db.session.get(Playlist, pl_id)
    if not pl or pl.owner_id != user.id:
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(force=True)
    song_id = data.get("song_id")
    song = db.session.get(Song, song_id)
    if not song or song.status != "approved":
        return jsonify({"error": "song not found"}), 404
    exists = PlaylistSong.query.filter_by(playlist_id=pl_id, song_id=song_id).first()
    if exists:
        return jsonify({"error": "already in playlist"}), 409
    pos = len(pl.items)
    ps = PlaylistSong(playlist_id=pl_id, song_id=song_id, position=pos)
    db.session.add(ps)
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/playlists/<int:pl_id>/songs/<int:song_id>", methods=["DELETE"])
@login_required
def api_playlist_remove_song(pl_id, song_id):
    user = get_current_user()
    pl = db.session.get(Playlist, pl_id)
    if not pl or pl.owner_id != user.id:
        return jsonify({"error": "forbidden"}), 403
    ps = PlaylistSong.query.filter_by(playlist_id=pl_id, song_id=song_id).first()
    if ps:
        db.session.delete(ps)
        db.session.commit()
    return jsonify({"ok": True})


# ─────────────────────────── File serving ────────────────────────────────── #

@app.route("/cover/<int:song_id>")
def serve_cover(song_id):
    song = db.session.get(Song, song_id)
    if not song or not song.cover_file_id:
        abort(404)
    key = song.cover_file_id.split(f"{S3_BUCKET}/", 1)[-1]
    url = s3_presign(key, expires=3600)
    if not url:
        abort(404)
    return redirect(url)

@app.route("/stream/<int:song_id>")
def stream_audio(song_id):
    song = db.session.get(Song, song_id)
    if not song or song.status != "approved" or not song.audio_file_id:
        abort(404)
    key = song.audio_file_id.split(f"{S3_BUCKET}/", 1)[-1]
    url = s3_presign(key, expires=3600)
    if not url:
        abort(500)
    range_header = request.headers.get("Range")
    req_headers = {}
    if range_header:
        req_headers["Range"] = range_header
    try:
        s3_resp = requests.get(url, headers=req_headers, stream=True, timeout=10)
    except Exception as e:
        print(f"[STREAM] error: {e}", flush=True)
        abort(500)
    headers = {
        "Content-Type": s3_resp.headers.get("Content-Type", "audio/mpeg"),
        "Accept-Ranges": "bytes",
        "Access-Control-Allow-Origin": "*",
    }
    if "Content-Length" in s3_resp.headers:
        headers["Content-Length"] = s3_resp.headers["Content-Length"]
    if "Content-Range" in s3_resp.headers:
        headers["Content-Range"] = s3_resp.headers["Content-Range"]
    return Response(
        stream_with_context(s3_resp.iter_content(chunk_size=65536)),
        status=s3_resp.status_code,
        headers=headers,
    )


# ─────────────────────────── Telegram Webhook ────────────────────────────── #

@app.route(f"/webhook/{WEBHOOK_SECRET}", methods=["POST"])
def telegram_webhook():
    data = request.get_json(force=True)

    msg = data.get("message", {})
    if msg:
        chat_id = msg["chat"]["id"]
        text = msg.get("text", "")
        from_user = msg.get("from", {})
        tg_id = from_user.get("id")
        if text.startswith("/start") and tg_id:
            user = User.query.filter_by(telegram_id=tg_id).first()
            if not user:
                user = User(telegram_id=tg_id,
                            telegram_username=from_user.get("username"),
                            telegram_first_name=from_user.get("first_name"))
                db.session.add(user)
                db.session.commit()
                greeting = "👋 Добро пожаловать в <b>HertMusic</b>!\n\n"
            else:
                greeting = "🎵 С возвращением в <b>HertMusic</b>!\n\n"
            tg("sendMessage", chat_id=chat_id, parse_mode="HTML",
               text=f"{greeting}Твой токен для входа на сайт:\n\n<code>{user.token}</code>\n\nВведи его на странице входа 👆")

    cb = data.get("callback_query", {})
    if cb:
        callback_id = cb["id"]
        cb_data = cb.get("data", "")
        from_user = cb.get("from", {})
        cb_from_id = str(from_user.get("id", ""))
        cb_from_uname = (from_user.get("username") or "").lower()
        if not ((cb_from_id in ADMIN_IDS) or (cb_from_uname in ADMIN_USERNAMES)):
            tg("answerCallbackQuery", callback_query_id=callback_id, text="⛔ Нет доступа")
            return "ok"
        if ":" in cb_data:
            action, song_id_str = cb_data.split(":", 1)
            song = db.session.get(Song, int(song_id_str))
            if song:
                if action == "approve":
                    song.status = "approved"
                    answer = f"✅ Принято: {song.title}"
                elif action == "reject":
                    song.status = "rejected"
                    answer = f"❌ Отклонено: {song.title}"
                else:
                    answer = "?"
                db.session.commit()
                tg("answerCallbackQuery", callback_query_id=callback_id, text=answer)
                msg_id = cb.get("message", {}).get("message_id")
                if msg_id:
                    tg("editMessageReplyMarkup", chat_id=cb_from_id,
                       message_id=msg_id, reply_markup={"inline_keyboard": []})
                notify_admins(answer)
            else:
                tg("answerCallbackQuery", callback_query_id=callback_id, text="Трек не найден")
    return "ok"


@app.route("/setup-webhook")
def setup_webhook():
    base_url = request.host_url.rstrip("/").replace("http://", "https://")
    webhook_url = f"{base_url}/webhook/{WEBHOOK_SECRET}"
    return jsonify({"webhook_url": webhook_url, "result": tg("setWebhook", url=webhook_url)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
