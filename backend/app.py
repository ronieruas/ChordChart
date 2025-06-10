import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# Habilita o CORS para permitir que o frontend se comunique com este backend
CORS(app)

DATABASE = 'songs.db'

def get_db():
    """ Conecta-se ao banco de dados. """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """ Cria a tabela do banco de dados se ela não existir. """
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()
        cursor.close()
        db.close()

@app.route('/api/songs', methods=['GET'])
def get_songs():
    """ Retorna uma lista de todas as músicas salvas. """
    db = get_db()
    cursor = db.cursor()
    songs = cursor.execute('SELECT id, title FROM songs ORDER BY title ASC').fetchall()
    cursor.close()
    db.close()
    return jsonify([dict(song) for song in songs])

@app.route('/api/songs/<int:song_id>', methods=['GET'])
def get_song(song_id):
    """ Retorna o conteúdo de uma música específica. """
    db = get_db()
    cursor = db.cursor()
    song = cursor.execute('SELECT content FROM songs WHERE id = ?', (song_id,)).fetchone()
    cursor.close()
    db.close()
    if song is None:
        return jsonify({'error': 'Song not found'}), 404
    return jsonify(dict(song))

@app.route('/api/songs', methods=['POST'])
def add_song():
    """ Salva uma nova música no banco de dados. """
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')

    if not title or not content:
        return jsonify({'error': 'Title and content are required'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO songs (title, content) VALUES (?, ?)', (title, content))
    db.commit()
    new_song_id = cursor.lastrowid
    cursor.close()
    db.close()
    return jsonify({'id': new_song_id, 'title': title}), 201

@app.route('/api/songs/<int:song_id>', methods=['DELETE'])
def delete_song(song_id):
    """ Deleta uma música do banco de dados. """
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM songs WHERE id = ?', (song_id,))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({'message': 'Song deleted successfully'})

# Inicializa o banco de dados na primeira vez que o servidor rodar
init_db()

if __name__ == '__main__':
    # Roda o servidor na porta 5000, acessível de fora do container
    app.run(host='0.0.0.0', port=5000)