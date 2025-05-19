from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)
users = {}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/auth', methods=['POST'])
def auth():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    hwid = data.get('hwid')

    if not username or not password or not hwid:
        return jsonify({'status': 'error', 'message': 'Missing data'}), 400

    pw_hash = hash_password(password)

    if username in users:
        if users[username]['password'] != pw_hash:
            return jsonify({'status': 'error', 'message': 'Invalid password'}), 401
        if users[username]['hwid'] != hwid:
            return jsonify({'status': 'error', 'message': 'HWID mismatch'}), 403
        return jsonify({'status': 'success', 'message': 'Authorized'}), 200
    else:
        users[username] = {
            'password': pw_hash,
            'hwid': hwid
        }
        return jsonify({'status': 'registered', 'message': 'User registered with HWID'}), 201

if __name__ == '__main__':
    app.run()
