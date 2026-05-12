import jwt
from datetime import datetime, timedelta, timezone


# if its less then 19 bytes, it throws a error that min key len ought to be 32 bytes
SECRET = "my-super-secret-key-my-super-secret-key-my-super-secret-key-"

# --- encode a JWT ---
# also known as claims
payload = {
    "user_id": 42,
    "username": "rohtanza",
    "role": "admin",
    # token expires after one hour
    "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    "iat": datetime.now(timezone.utc),
}

token = jwt.encode(payload, SECRET, algorithm="HS256")
print("Encoded Token:")
print(token)
print()

# --- decode a JWT ---
decoded = jwt.decode(token, SECRET, algorithms=["HS256"])
print("Decoded Payload:")
print(decoded)
print()

# --- decode without verification (unsafe, for inspection only) ---
unverified = jwt.decode(token, options={"verify_signature": False})
print("Unverified Decode:")
print(unverified)
print()

# --- expired token example ---
expired_payload = {
    "user_id": 1,
    "exp": datetime.now(timezone.utc) - timedelta(hours=1),
}
expired_token = jwt.encode(expired_payload, SECRET, algorithm="HS256")

try:
    jwt.decode(expired_token, SECRET, algorithms=["HS256"])
except jwt.ExpiredSignatureError:
    print("Caught ExpiredSignatureError — token is expired!")

# --- invalid token example ---
try:
    jwt.decode("not.a.real.token", SECRET, algorithms=["HS256"])
except jwt.DecodeError:
    print("Caught DecodeError — token is invalid!")
