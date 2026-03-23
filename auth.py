import hashlib

users_db = {}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register(username, password):
    users_db[username] = hash_password(password)

def login(username, password):
    return users_db.get(username) == hash_password(password)