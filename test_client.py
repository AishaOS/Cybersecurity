import jwt
import requests
import base64


# Helper function
def send_request(method, url, **kwargs):
    try:
        response = requests.request(method, url, **kwargs)
        return response
    except requests.ConnectionError as e:
        print(f"Error connecting to {url}. Details: {e}")
        return None


# JWT Authentication tests
def test_auth_endpoint_valid():
    response = send_request("POST", "http://localhost:8080/auth")
    if response and response.status_code == 200:
        print("Received JWT:", response.text)
    elif response:
        print("Error:", response.text)


def test_auth_endpoint_expired():
    pass


def test_jwks_endpoint():
    response = requests.get("http://localhost:8080/.well-known/jwks.json")
    if response.status_code == 200:
        try:
            print("Received JWKS:", response.json())
        except requests.exceptions.JSONDecodeError:
            print("Received response was not valid JSON:", response.text)
    else:
        print("Error:", response.text)


def test_with_basic_auth():
    credentials = base64.b64encode(b"userABC:password123").decode('utf-8')
    response = requests.get("http://localhost:8080/your_endpoint", headers={"Authorization": f"Basic {credentials}"})

    # Debugging statements
    print(f"[Basic Auth] Received status code: {response.status_code}")
    print(f"[Basic Auth] Response body: {response.text}")

    assert response.status_code == 200, "Unexpected status code!"
    assert "your_jwt_token_key" in response.json(), "JWT token not found in the response!"

def test_with_json_payload():
    payload = {
        "username": "userABC",
        "password": "password123"
    }
    response = requests.post("http://localhost:8080/your_endpoint", json=payload)

    # Debugging statements
    print(f"[JSON Payload] Received status code: {response.status_code}")
    print(f"[JSON Payload] Response body: {response.text}")

    assert response.status_code == 200, "Unexpected status code!"
    assert "your_jwt_token_key" in response.json(), "JWT token not found in the response!"

# Database tests
def test_db_file_access():
    try:
        with open("totally_not_my_privateKeys.db", "rb") as db_file:  # Note the 'b' in the mode for binary
            # Maybe do a simple read and write to ensure accessibility
            content = db_file.read()
            db_file.write(content)
    except Exception as e:
        assert False, f"Error accessing the DB file: {e}"

if __name__ == "__main__":
    test_auth_endpoint_valid()
    test_auth_endpoint_expired()
    test_jwks_endpoint()
    test_with_basic_auth()
    test_with_json_payload()
    test_db_file_access()