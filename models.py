from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.BigInteger, unique=True, nullable=False)
    telegram_username = db.Column(db.String(100))
    telegram_first_name = db.Column(db.String(100))
    token = db.Column(db.String(64), unique=True, default=lambda: secrets.token_urlsafe(32))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    songs = db.relationship("Song", backref="uploader", lazy=True)
    playlists = db.relationship("Playlist", backref="owner", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "telegram_username": self.telegram_username,
            "telegram_first_name": self.telegram_first_name,
        }

class Song(db.Model):
    __tablename__ = "songs"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    artist = db.Column(db.String(200), nullable=False)
    cover_file_id = db.Column(db.String(500))
    audio_file_id = db.Column(db.String(500))
    status = db.Column(db.String(20), default="pending")
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    review_message_id = db.Column(db.BigInteger)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "artist": self.artist,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }

class Playlist(db.Model):
    __tablename__ = "playlists"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(300), default="")
    is_public = db.Column(db.Boolean, default=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship("PlaylistSong", backref="playlist", lazy=True,
                            order_by="PlaylistSong.position", cascade="all, delete-orphan")

    def to_dict(self, with_songs=False):
        d = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_public": self.is_public,
            "owner_id": self.owner_id,
            "owner_name": self.owner.telegram_first_name or self.owner.telegram_username or "?",
            "song_count": len(self.items),
            "created_at": self.created_at.isoformat(),
        }
        if with_songs:
            d["songs"] = [item.song.to_dict() for item in self.items if item.song]
        return d

class PlaylistSong(db.Model):
    __tablename__ = "playlist_songs"
    id = db.Column(db.Integer, primary_key=True)
    playlist_id = db.Column(db.Integer, db.ForeignKey("playlists.id"), nullable=False)
    song_id = db.Column(db.Integer, db.ForeignKey("songs.id"), nullable=False)
    position = db.Column(db.Integer, default=0)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    song = db.relationship("Song")
