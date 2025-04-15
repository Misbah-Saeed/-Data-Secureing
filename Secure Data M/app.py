import streamlit as st
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

DATA_FILE = "secure_data.json"
LOCKOUT_DURATION = 60  # in seconds

# Initialize session state
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = {}
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = {}

# Load or initialize data file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

data = load_data()

# Secure key generation with PBKDF2
def derive_key(passkey, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(passkey.encode()))

# Encryption & decryption
def encrypt_data(text, key):
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, key):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_text.encode()).decode()

# Authentication helpers
def register_user(username, password):
    if username in data:
        return False
    salt = os.urandom(16).hex()
    key = derive_key(password, salt).decode()
    data[username] = {"salt": salt, "key": key, "entries": []}
    save_data(data)
    return True

def authenticate_user(username, password):
    if username not in data:
        return False
    salt = data[username]['salt']
    key = derive_key(password, salt).decode()
    return key == data[username]['key']

# Lockout check
def is_locked_out(username):
    if username not in st.session_state.lockout_time:
        return False
    if time.time() - st.session_state.lockout_time[username] < LOCKOUT_DURATION:
        return True
    else:
        st.session_state.failed_attempts[username] = 0
        return False

# UI
st.title("🔐  Data Secureing ")

menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home
if choice == "Home":
    st.subheader("💿 Welcome To Data Secureing ")
    st.write("Encrypted data system with multi-user access and advanced security protocols.")

# Register
elif choice == "Register":
    st.subheader("🆕 Register")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")

    if st.button("Create Account"):
        if register_user(new_user, new_pass):
            st.success(" 🎉Congratulation registered successfully!")
        else:
            st.error("⚠️ Username already exists.")

# Login
elif choice == "Login":
    st.subheader("📌 Login")
    user = st.text_input("Username")
    passwd = st.text_input("Password", type="password")

    if is_locked_out(user):
        st.warning("⏱ Too many failed attempts. Try again later.")
    elif st.button("Login"):
        if authenticate_user(user, passwd):
            st.session_state.current_user = user
            st.session_state.failed_attempts[user] = 0
            st.success(f"🧿 Welcome   {user}!")
        else:
            st.session_state.failed_attempts[user] = st.session_state.failed_attempts.get(user, 0) + 1
            attempts_left = 3 - st.session_state.failed_attempts[user]
            st.error(f"❌ Incorrect credentials. Attempts left: {attempts_left}")
            if attempts_left <= 0:
                st.session_state.lockout_time[user] = time.time()

# Logout
elif choice == "Logout":
    st.session_state.current_user = None
    st.success("🎉 Logged out successfully.")

# Store Data
elif choice == "Store Data":
    if not st.session_state.current_user:
        st.warning("↥ Please login to store data.")
    else:
        st.subheader("📦 Store Your Data")
        user_input = st.text_area("Enter Data to Encrypt")
        if st.button("Encrypt & Store"):
            user = st.session_state.current_user
            key = derive_key(data[user]["key"], data[user]["salt"])
            encrypted = encrypt_data(user_input, key)
            data[user]["entries"].append(encrypted)
            save_data(data)
            st.success("✅ Data encrypted and stored.")
            st.text(f"Encrypted Text: {encrypted}")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.current_user:
        st.warning(" ↥ Please login to retrieve data.")
    else:
        st.subheader("🔍 Your Encrypted Entries")
        user = st.session_state.current_user
        key = derive_key(data[user]["key"], data[user]["salt"])
        for idx, entry in enumerate(data[user]["entries"]):
            if st.button(f"Decrypt Entry {idx + 1}"):
                decrypted = decrypt_data(entry, key)
                st.info(f"🔓 Decrypted: {decrypted}")


