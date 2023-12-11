from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
import base64
import json
import datetime
import jwt
import sqlite3
import os 

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the derived key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

aes_key_hex = os.environ.get('NOT_MY_KEY', '')
aes_key = bytes.fromhex(aes_key_hex)
print("AES Key Length:", len(aes_key))

# Example password and salt
password = b"your-password"
salt = os.urandom(16)  # Generate a random salt

derived_key = derive_key(password, salt)
print("Derived Key:", derived_key.hex())

hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def get_private_key_for_auth(expired=False):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    if expired:
        cursor.execute("SELECT key_data FROM private_keys WHERE expiration_time < ?",
                       (datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),))
    else:
        cursor.execute("SELECT key_data FROM private_keys WHERE expiration_time >= ?",
                       (datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),))

    key_data = cursor.fetchone()
    conn.close()

    if key_data:
        return key_data[0]
    return None

def aes_encrypt(key_data):
    aes_key_hex = os.environ.get('NOT_MY_KEY')
    if not aes_key_hex:
        raise ValueError("AES key not found in environment variables.")

    # Convert hexadecimal key to bytes
    aes_key = bytes.fromhex(aes_key_hex)

    if len(aes_key) not in [16, 24, 32]:
        raise ValueError("Invalid AES key. Key must be 16, 24, or 32 bytes long.")

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data
    padder = padding.PKCS7(128).padder()  # 128-bit padding for AES block size
    padded_data = padder.update(key_data) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data, iv



def aes_decrypt(encrypted_data, iv):
    aes_key = os.environ.get('NOT_MY_KEY', '').encode('utf-8')
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())

    decryptor = cipher.decryptor()  # Create a decryptor instance
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()  # Unpad the data
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

def get_all_valid_private_keys():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("SELECT key_data FROM private_keys WHERE expiration_time >= ?",
                   (datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),))

    keys_data = cursor.fetchall()
    conn.close()

    if keys_data:
        return [key[0] for key in keys_data]
    return []


def validate_jwt(token, key_data):
    try:
        decoded = jwt.decode(token, key_data, algorithms='RS256')
        return True, decoded
    except jwt.ExpiredSignatureError:
        return False, "Token has expired"
    except jwt.InvalidTokenError:
        return False, "Invalid token"


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def generate_jwt(key, expired=False):
        # Assuming you want to include some data in the JWT
        payload = {
            "user": "sampleUser",
            "isAdmin": False,
            "iat": datetime.datetime.utcnow(),
            # Optionally, set the expiration of the JWT
            "exp": datetime.datetime.utcnow() + datetime.timedelta(
                hours=1) if not expired else datetime.datetime.utcnow() - datetime.timedelta(minutes=5)
        }

        # Generate the JWT. Replace 'HS256' with the algorithm you want.
        token = jwt.encode(payload, key, algorithm='RS256')
        return token

    def do_POST(self):
        print("Received a POST request for:", self.path)
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        path = parsed_path.path

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')


        # Handle /auth endpoint:
        if path == "/auth":
            if not post_data.strip():
                print("Received empty POST data.")
                self.send_response(400, "Bad Request: No data sent")
                self.end_headers()
                return 
                

            # For simplicity, let's assume a valid user always sends {"user": "admin", "password": "password"} as JSON.
            try:
                data = json.loads(post_data)
                if data.get("user") == "admin" and data.get("password") == "password":
                    # Use the right key based on the expired param
                    key_data = get_private_key_for_auth(expired="expired" in params)
                    token = self.generate_jwt(key_data, expired="expired" in params)
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(bytes(token, "utf-8"))
                else:
                    self.send_response(403)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"Invalid credentials")
                return
            except json.JSONDecodeError:
                print("Failed to decode JSON from POST data.")
                self.send_response(400, "Bad Request: Data is not valid JSON")
                self.end_headers()
                return

        self.send_response(405)
        self.end_headers()
        return
    
    def do_POST_register(self, post_data):
        try:
            data = json.loads(post_data)

            # Extract username and email from the request data
            username = data.get("username")
            email = data.get("email")

            # Generate a secure password, for example using UUID
            password = str(uuid.uuid4())

            # Hash the password before storing it (use a secure hashing algorithm)
            hashed_password = hash_password(password)  # Implement hash_password method

            # Store the new user in the database
            conn = sqlite3.connect('my_database.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", 
                        (username, hashed_password, email))
            conn.commit()
            conn.close()

            # Send the generated password back to the user
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"password": password}
            self.wfile.write(bytes(json.dumps(response), "utf-8"))

        except json.JSONDecodeError:
            self.send_response(400, "Bad Request: Data is not valid JSON")
            self.end_headers()
        except sqlite3.Error as e:
            # Handle database errors
            print(f"Database error: {e}")
            self.send_response(500, "Internal Server Error")
            self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            valid_private_keys = get_all_valid_private_keys()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(load_pem_private_key(key.encode('utf-8'),
                                                                password=None,
                                                                backend=default_backend()).private_numbers().public_numbers.n),
                        "e": int_to_base64(load_pem_private_key(key.encode('utf-8'),
                                                                password=None,
                                                                backend=default_backend()).private_numbers().public_numbers.e),
                    } for key in valid_private_keys
                ]
            }

            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        elif self.path.startswith("/validate"):
            parsed_path = urlparse(self.path)
            params = parse_qs(parsed_path.query)
            token = params.get("token", [None])[0]  # get the token query param

            if not token and "Authorization" in self.headers:
                token = self.headers["Authorization"].replace("Bearer ", "")

            if not token:
                self.send_response(400)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Token not provided")
                return

            # Fetching the private key data for decoding the JWT.
            # Note: In a real-world scenario, you'd match the 'kid' of the JWT header with the one in your database.
            key_data = get_private_key_for_auth()

            valid, message = validate_jwt(token, key_data)

            if valid:
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps(message), "utf-8"))
            else:
                self.send_response(401)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(bytes(message, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


def initialize_keys_database():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    # Modify this query to add the 'iv' column to your table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS private_keys (
        id INTEGER PRIMARY KEY,
        key_name TEXT NOT NULL,
        key_data BLOB NOT NULL,  -- Changed to BLOB to store binary data
        iv BLOB NOT NULL,        -- New column for the IV
        expiration_time DATETIME
    )
    ''')
    conn.commit()
    conn.close()


initialize_keys_database()


def initialize_database():
    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        email TEXT UNIQUE,
                        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_ip TEXT NOT NULL,
                        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        user_id INTEGER,
                        FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

initialize_database()


def insert_key(key_name, key_data, expiration_time=None):
    encrypted_data, iv = aes_encrypt(key_data.encode('utf-8'))
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO private_keys (key_name, key_data, iv, expiration_time) VALUES (?, ?, ?, ?)", 
                   (key_name, encrypted_data, iv, expiration_time))
    conn.commit()
    conn.close()


insert_key("my_key", pem.decode('utf-8'), (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'))
insert_key("expired_key", expired_pem.decode('utf-8'), (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'))


def get_private_key(key_name):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("SELECT key_data, iv FROM private_keys WHERE key_name = ?", (key_name,))
    row = cursor.fetchone()
    conn.close()

    if row:
        key_data, iv = row
        return aes_decrypt(key_data, iv)
    return None



# Example usage
retrieved_key = get_private_key("my_key")
print(retrieved_key)

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")