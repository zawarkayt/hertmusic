from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.BigInteger, unique=True, nullable=False)
    telegram_username = db.Column(db.String(100))
    telegram_first_name = db.Column(db.String(100))
    token = db.Column(db.String(64), unique=True, default=lambda: secrets.token_urlsafe(32))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    songs = db.relationship('Song', backref='uploader', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'telegram_username': self.telegram_username,
            'telegram_first_name': self.telegram_first_name,
        }

class Song(db.Model):
    __tablename__ = 'songs'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    artist = db.Column(db.String(200), nullable=False)
    cover_file_id = db.Column(db.String(300))
    audio_file_id = db.Column(db.String(300))
    status = db.Column(db.String(20), default='pending')  # pending / approved / rejected
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    review_message_id = db.Column(db.BigInteger)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'artist': self.artist,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
        }
