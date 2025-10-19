import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

key = b"0123456789abcdef0123456789abcdef"

@app.route('/encrypt', methods=['POST'])
def encrypt_handler():
    try:
        req = request.get_json()
        text = req['text']
        
        nonce = os.urandom(16)
        
        algorithm = algorithms.AES(key)
        cipher = Cipher(algorithm, modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
        
        combined = nonce + ciphertext + encryptor.tag
        
        encoded = base64.b64encode(combined).decode('utf-8')
        
        return jsonify({"ciphertext": encoded})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_handler():
    try:
        req = request.get_json()
        ciphertext_b64 = req['ciphertext']
        
        data = base64.b64decode(ciphertext_b64)
        
        nonce = data[:16]
        ciphertext = data[16:-16]
        tag = data[-16:]
        
        algorithm = algorithms.AES(key)
        cipher = Cipher(algorithm, modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return jsonify({"text": plaintext.decode('utf-8')})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
