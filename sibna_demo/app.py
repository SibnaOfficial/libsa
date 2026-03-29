import os
import sys
from flask import Flask, render_template, request, jsonify

# Add parent directory to path to import sibna
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    import sibna
    from sibna.client import Identity
except ImportError:
    print("Error importing sibna")
    sys.exit(1)

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/version', methods=['GET'])
def get_version():
    return jsonify({"protocol_version": sibna.Context.version(), "sdk_version": "1.0.4"})

@app.route('/api/generate_identity', methods=['POST'])
def generate_identity():
    id = Identity()
    return jsonify({"public_key": id.public_key_hex})

@app.route('/api/encrypt', methods=['POST'])
def encrypt_message():
    data = request.json
    plaintext = data.get('plaintext', '').encode('utf-8')
    key = sibna.generate_key()
    ciphertext = sibna.encrypt(key, plaintext)
    return jsonify({"ciphertext": ciphertext.hex(), "key": key.hex()})

@app.route('/api/decrypt', methods=['POST'])
def decrypt_message():
    data = request.json
    ciphertext = bytes.fromhex(data.get('ciphertext', ''))
    key = bytes.fromhex(data.get('key', ''))
    plaintext = sibna.decrypt(key, ciphertext)
    return jsonify({"plaintext": plaintext.decode('utf-8')})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
