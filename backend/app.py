import os
import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
CORS(app, supports_credentials=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'songs.db'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor()
    user_data = cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    cursor.close()
    db.close()
    if user_data:
        return User(id=user_data['id'], username=user_data['username'])
    return None

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                original_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )''')
        db.commit()
        cursor.close()
        db.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    db = get_db()
    cursor = db.cursor()
    user_data = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    cursor.close()
    db.close()
    if user_data and check_password_hash(user_data['password_hash'], password):
        user = User(id=user_data['id'], username=user_data['username'])
        login_user(user)
        return jsonify({"message": "Login successful", "user": {"username": user.username}})
    return jsonify({"error": "Credenciais inválidas"}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successful"})

@app.route('/api/check_auth', methods=['GET'])
def check_auth():
    if current_user.is_authenticated:
        return jsonify({"is_logged_in": True, "user": {"username": current_user.username}})
    return jsonify({"is_logged_in": False})

@app.route('/api/songs', methods=['GET'])
@login_required
def get_songs():
    db = get_db()
    cursor = db.cursor()
    songs = cursor.execute('SELECT id, title, original_key FROM songs ORDER BY title ASC').fetchall()
    cursor.close()
    db.close()
    return jsonify([dict(song) for song in songs])

@app.route('/api/songs/<int:song_id>', methods=['GET'])
@login_required
def get_song(song_id):
    db = get_db()
    cursor = db.cursor()
    song = cursor.execute('SELECT content FROM songs WHERE id = ?', (song_id,)).fetchone()
    cursor.close()
    db.close()
    if song is None: return jsonify({'error': 'Song not found'}), 404
    return jsonify(dict(song))

@app.route('/api/songs', methods=['POST'])
@login_required
def add_song():
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    original_key = data.get('original_key')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO songs (title, content, original_key) VALUES (?, ?, ?)',
                   (title, content, original_key))
    db.commit()
    new_song_id = cursor.lastrowid
    cursor.close()
    db.close()
    return jsonify({'id': new_song_id, 'title': title}), 201

@app.route('/api/songs/<int:song_id>', methods=['DELETE'])
@login_required
def delete_song(song_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM songs WHERE id = ?', (song_id,))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({'message': 'Song deleted successfully'})

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)