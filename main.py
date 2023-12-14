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

# Server Configuration
hostName = "127.0.0.1"
serverPort = 8080

# RSA Key Generation
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

def initialize_database():
    conn = sqlite3.connect('my_database.db')
    cursor = conn.cursor()
    # Create tables
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS private_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, key_data BLOB NOT NULL, iv BLOB NOT NULL, expiration_time DATETIME)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, request_ip TEXT NOT NULL, request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

initialize_database()

# Utility Functions
def int_to_base64(value):
    # Convert an integer to a Base64URL-encoded string
    # """Convert an integer to a Base64URL-encoded string"""
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

def get_private_key(key_name):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("SELECT key_data FROM private_keys WHERE key_name = ?", (key_name,))
    key_data = cursor.fetchone()
    conn.close()

    if key_data:
        return key_data[0]
    return None

class MyServer(BaseHTTPRequestHandler):
    _rate_limit_info = {}  # For rate limiting

    def check_rate_limit(self, client_ip):
        current_time = datetime.datetime.now()
        if client_ip in self._rate_limit_info:
         last_request_time = self._rate_limit_info[client_ip]
        if (current_time - last_request_time).seconds < 60:  # 60 seconds limit
            return False  # Rate limit exceeded
        self._rate_limit_info[client_ip] = current_time
        return True  

    def send_json_response(self, code, data):
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(bytes(json.dumps(data), "utf-8"))

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

    def do_POST(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == "/register":
            self.handle_register_request()
        elif path == "/auth":
            self.handle_auth_request()
        else:
            self.send_response(405)
            self.end_headers()

    def handle_register_request(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        try:
            data = json.loads(post_data)
            # Extracting the username, password, and email from the POST data
            username = data.get('username')
            password = data.get('password')  # In a real application, hash this password
            email = data.get('email', '')    # Email is optional

            # Input validation
            if not username or not password:
                self.send_json_response(400, {"message": "Username and password are required"})
                return

            # Insert the new user into the database
            conn = sqlite3.connect('my_database.db')
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                               (username, password, email))
                conn.commit()
            except sqlite3.IntegrityError:
                self.send_json_response(400, {"message": "Username already exists"})
                return
            finally:
                conn.close()

            self.send_json_response(201, {"message": "User registered successfully"})
        except json.JSONDecodeError:
            self.send_json_response(400, {"message": "Invalid JSON data"})
        except Exception as e:
            self.send_json_response(500, {"message": f"Internal server error: {str(e)}"})

        self.send_response(201)  # Set the status code
        self.send_header("Content-type", "application/json")  # Set the content type header
        self.end_headers()
        response_data = {"message": "User registered successfully"}
        self.wfile.write(bytes(json.dumps(response_data), "utf-8"))  # Send the response data    

    def handle_auth_request(self, post_data):
        try:
            data = json.loads(post_data)
            if data.get("user") == "admin" and data.get("password") == "password":
                key_data = get_private_key_for_auth(expired="expired" in params)
                token = generate_jwt(key_data, expired="expired" in params)
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(bytes(token, "utf-8"))
            else:
                self.send_response(403)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Invalid credentials")
        except json.JSONDecodeError:
            print("Failed to decode JSON from POST data.")
            self.send_response(400, "Bad Request: Data is not valid JSON")
            self.end_headers()
        except Exception as e:
            print(f"Error handling auth request: {str(e)}")
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
        _rate_limit_info = {}
        def check_rate_limit(self, client_ip):
            current_time = datetime.datetime.now()
        if client_ip in self._rate_limit_info:
            last_request_time = self._rate_limit_info[client_ip]
            if (current_time - last_request_time).seconds < 60:  # 60 seconds limit
                return False  # Rate limit exceeded
        self._rate_limit_info[client_ip] = current_time
        return True    

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

    def handle_auth_request(self, post_data):
        try:
            data = json.loads(post_data)
            if data.get("user") == "admin" and data.get("password") == "password":
                key_data = get_private_key_for_auth(expired="expired" in params)
                token = generate_jwt(key_data, expired="expired" in params)
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(bytes(token, "utf-8"))
            else:
                self.send_response(403)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Invalid credentials")
        except json.JSONDecodeError:
            print("Failed to decode JSON from POST data.")
            self.send_response(400, "Bad Request: Data is not valid JSON")
            self.end_headers()
        except Exception as e:
            print(f"Error handling auth request: {str(e)}")
            self.send_response(500)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
        _rate_limit_info = {}
        def check_rate_limit(self, client_ip):
            current_time = datetime.datetime.now()
        if client_ip in self._rate_limit_info:
            last_request_time = self._rate_limit_info[client_ip]
            if (current_time - last_request_time).seconds < 60:  # 60 seconds limit
                return False  # Rate limit exceeded
        self._rate_limit_info[client_ip] = current_time
        return True 
    
    def initialize_database():
        conn = sqlite3.connect('your_database.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                username TEXT NOT NULL UNIQUE,
                                password_hash TEXT NOT NULL,
                                email TEXT UNIQUE,
                                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                last_login TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS private_keys (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                key_data BLOB NOT NULL,
                                iv BLOB NOT NULL, 
                                expiration_time DATETIME)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS auth_logs (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                request_ip TEXT NOT NULL,
                                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                user_id INTEGER,
                                FOREIGN KEY(user_id) REFERENCES users(id))''')
        conn.commit()
        conn.close()

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
