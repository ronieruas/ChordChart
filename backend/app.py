import os
import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
CORS(app, supports_credentials=True)

login_manager = LoginManager()
login_manager.init_app(app)
DATABASE = 'songs.db'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user_data = db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    if user_data: return User(id=user_data['id'], username=user_data['username'])
    return None

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
                content TEXT NOT NULL, original_key TEXT, user_id INTEGER, is_public BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS set_lists (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                user_id INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS set_list_songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, set_list_id INTEGER NOT NULL,
                song_id INTEGER NOT NULL, song_order INTEGER NOT NULL,
                FOREIGN KEY(set_list_id) REFERENCES set_lists(id) ON DELETE CASCADE,
                FOREIGN KEY(song_id) REFERENCES songs(id) ON DELETE CASCADE
            )''')
        conn.commit()
        conn.close()

# --- AUTH & USER MANAGEMENT ROUTES ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    db = get_db()
    user_data = db.execute("SELECT * FROM users WHERE username = ?", (data.get('username'),)).fetchone()
    db.close()
    if user_data and check_password_hash(user_data['password_hash'], data.get('password')):
        user = User(id=user_data['id'], username=user_data['username'])
        login_user(user)
        return jsonify({"user": {"username": user.username, "is_admin": user.username == 'admin'}})
    return jsonify({"error": "Credenciais inválidas"}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successful"})

@app.route('/api/check_auth', methods=['GET'])
def check_auth():
    if current_user.is_authenticated:
        return jsonify({"is_logged_in": True, "user": {"username": current_user.username, "is_admin": current_user.username == 'admin'}})
    return jsonify({"is_logged_in": False})

@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    if current_user.username != 'admin': return jsonify({"error": "Acesso não autorizado"}), 403
    data = request.get_json()
    password_hash = generate_password_hash(data.get('password'))
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (data.get('username'), password_hash))
        conn.commit()
        return jsonify({"message": f"Usuário '{data.get('username')}' criado com sucesso!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": f"O usuário '{data.get('username')}' já existe."}), 409
    finally:
        conn.close()

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    if current_user.username != 'admin': return jsonify({"error": "Acesso não autorizado"}), 403
    db = get_db()
    users = db.execute('SELECT id, username FROM users ORDER BY username ASC').fetchall()
    db.close()
    return jsonify([dict(user) for user in users])

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if current_user.username != 'admin': return jsonify({"error": "Acesso não autorizado"}), 403
    conn = get_db()
    user_to_delete = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if user_to_delete and user_to_delete['username'] == 'admin': return jsonify({"error": "Não é permitido deletar o usuário administrador"}), 403
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Usuário deletado com sucesso'})

@app.route('/api/users/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    conn = get_db()
    user_data = conn.execute("SELECT password_hash FROM users WHERE id = ?", (current_user.id,)).fetchone()
    if not check_password_hash(user_data['password_hash'], data.get('old_password')):
        conn.close()
        return jsonify({"error": "Senha antiga incorreta"}), 401
    new_password_hash = generate_password_hash(data.get('new_password'))
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, current_user.id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Senha alterada com sucesso"})

# --- SONGS API ROUTES ---
@app.route('/api/songs', methods=['GET'])
@login_required
def get_songs_filtered():
    filter_type = request.args.get('filter', 'my_songs')
    db = get_db()
    if filter_type == 'public':
        songs = db.execute('SELECT id, title, original_key, user_id FROM songs WHERE is_public = 1 ORDER BY title ASC').fetchall()
    else: 
        songs = db.execute('SELECT id, title, original_key, user_id FROM songs WHERE user_id = ? ORDER BY title ASC', (current_user.id,)).fetchall()
    db.close()
    return jsonify([dict(song) for song in songs])

@app.route('/api/songs', methods=['POST'])
@login_required
def add_song():
    data = request.get_json()
    conn = get_db()
    conn.execute('INSERT INTO songs (title, content, original_key, user_id, is_public) VALUES (?, ?, ?, ?, ?)', (data.get('title'), data.get('content'), data.get('original_key'), current_user.id, data.get('is_public', False)))
    conn.commit()
    conn.close()
    return jsonify({"message": "Música salva com sucesso!"}), 201

@app.route('/api/songs/<int:song_id>', methods=['DELETE'])
@login_required
def delete_song(song_id):
    conn = get_db()
    song = conn.execute("SELECT user_id FROM songs WHERE id = ?", (song_id,)).fetchone()
    if not song or song['user_id'] != current_user.id:
        conn.close()
        return jsonify({"error": "Acesso não autorizado"}), 403
    conn.execute('DELETE FROM songs WHERE id = ?', (song_id,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Música deletada com sucesso'})

@app.route('/api/songs/<int:song_id>', methods=['GET'])
@login_required
def get_song(song_id):
    db = get_db()
    song = db.execute('SELECT content FROM songs WHERE id = ?', (song_id,)).fetchone()
    db.close()
    if song is None: return jsonify({'error': 'Song not found'}), 404
    return jsonify(dict(song))

# --- SET LIST API ROUTES ---
@app.route('/api/setlists', methods=['GET'])
@login_required
def get_set_lists():
    db = get_db()
    lists = db.execute("SELECT id, name FROM set_lists WHERE user_id = ? ORDER BY name ASC", (current_user.id,)).fetchall()
    db.close()
    return jsonify([dict(row) for row in lists])

@app.route('/api/setlists', methods=['POST'])
@login_required
def create_set_list():
    data = request.get_json()
    name = data.get('name')
    if not name: return jsonify({"error": "Nome do Set List é obrigatório"}), 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO set_lists (name, user_id) VALUES (?, ?)", (name, current_user.id))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return jsonify({"id": new_id, "name": name}), 201

@app.route('/api/setlists/<int:list_id>', methods=['DELETE'])
@login_required
def delete_set_list(list_id):
    conn = get_db()
    set_list = conn.execute("SELECT * FROM set_lists WHERE id = ? AND user_id = ?", (list_id, current_user.id)).fetchone()
    if not set_list: conn.close(); return jsonify({"error": "Set List não encontrado ou não autorizado"}), 404
    conn.execute("DELETE FROM set_lists WHERE id = ?", (list_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Set List deletado com sucesso"})
    
@app.route('/api/setlists/<int:list_id>/rename', methods=['PUT'])
@login_required
def rename_set_list(list_id):
    data = request.get_json()
    new_name = data.get('name')
    if not new_name: return jsonify({"error": "Novo nome é obrigatório"}), 400
    conn = get_db()
    conn.execute("UPDATE set_lists SET name = ? WHERE id = ? AND user_id = ?", (new_name, list_id, current_user.id))
    conn.commit()
    conn.close()
    return jsonify({"id": list_id, "name": new_name})

@app.route('/api/setlists/<int:list_id>/songs', methods=['GET'])
@login_required
def get_songs_in_set_list(list_id):
    db = get_db()
    songs = db.execute("SELECT s.id, s.title, sls.song_order FROM songs s JOIN set_list_songs sls ON s.id = sls.song_id WHERE sls.set_list_id = ? ORDER BY sls.song_order ASC", (list_id,)).fetchall()
    db.close()
    return jsonify([dict(row) for row in songs])

@app.route('/api/setlists/<int:list_id>/songs', methods=['POST'])
@login_required
def add_song_to_set_list(list_id):
    data = request.get_json()
    song_id = data.get('song_id')
    conn = get_db()
    max_order_result = conn.execute("SELECT MAX(song_order) FROM set_list_songs WHERE set_list_id = ?", (list_id,)).fetchone()
    new_order = (max_order_result[0] or 0) + 1
    conn.execute("INSERT INTO set_list_songs (set_list_id, song_id, song_order) VALUES (?, ?, ?)", (list_id, song_id, new_order))
    conn.commit()
    conn.close()
    return jsonify({"message": "Música adicionada ao Set List"}), 201

@app.route('/api/setlists/<int:list_id>/songs/<int:song_id>', methods=['DELETE'])
@login_required
def remove_song_from_set_list(list_id, song_id):
    conn = get_db()
    conn.execute("DELETE FROM set_list_songs WHERE set_list_id = ? AND song_id = ?", (list_id, song_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Música removida do Set List"})

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)