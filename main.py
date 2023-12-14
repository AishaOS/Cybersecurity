from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from urllib.parse import urlparse, parse_qs
import base64
import json
import datetime
import jwt
import sqlite3

hostName = "127.0.0.1"
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
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS private_keys (
        id INTEGER PRIMARY KEY,
        key_name TEXT NOT NULL,
        key_data TEXT NOT NULL,
        expiration_time DATETIME
    )
    ''')
    conn.commit()
    conn.close()
initialize_keys_database()


def initialize_database():
    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    # tokens table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY,
        token TEXT NOT NULL,
        user TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    # private_keys table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS private_keys (
        id INTEGER PRIMARY KEY,
        key_name TEXT NOT NULL,
        key_data TEXT NOT NULL,
        expiration_time DATETIME
    )
    ''')
    conn.commit()
    conn.close()

initialize_database()


def insert_key(key_name, key_data, expiration_time=None):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO private_keys (key_name, key_data, expiration_time) VALUES (?, ?, ?)", (key_name, key_data, expiration_time))
    conn.commit()
    conn.close()


insert_key("my_key", pem.decode('utf-8'), (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'))
insert_key("expired_key", expired_pem.decode('utf-8'), (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'))


def get_private_key(key_name):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("SELECT key_data FROM private_keys WHERE key_name = ?", (key_name,))
    key_data = cursor.fetchone()
    conn.close()

    if key_data:
        return key_data[0]
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