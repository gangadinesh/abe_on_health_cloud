from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from charm.schemes.abenc import cpabe

app = Flask(__name__)

# Set up Attribute-Based Encryption
master_key = cpabe.setup()
public_key = cpabe.extractPublic(master_key)
secret_key = None  # In a real application, manage secret keys securely.

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.form['data']
    policy = request.form['policy']

    # Perform Attribute-Based Encryption
    aes_key = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))

    cpabe_cipher = cpabe.CPABELSW06(public_key)
    cpabe_policy = cpabe.parsePolicy(policy)
    secret_key = cpabe.keygen(public_key, master_key, cpabe_policy)
    cpabe_ciphertext = cpabe.encrypt(public_key, aes_key, cpabe_policy)

    return render_template('result.html', ciphertext=ciphertext.hex(), cpabe_ciphertext=cpabe_ciphertext)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    ciphertext_hex = request.form['ciphertext']
    cpabe_ciphertext = request.form['cpabe_ciphertext']

    ciphertext = bytes.fromhex(ciphertext_hex)

    # Perform Attribute-Based Decryption
    aes_key = cpabe.decrypt(public_key, secret_key, cpabe_ciphertext)
    cipher = AES.new(aes_key, AES.MODE_CBC)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return render_template('result.html', decrypted_data=decrypted_data.decode())

if __name__ == '__main__':
    app.run(debug=True)
