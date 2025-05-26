import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"  # You can improve this with a user-specific salt for better security
LOCKOUT_DURATION = 60  # Lockout duration after failed login attempts

# Initialize session state variables if they don't exist
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
    
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
        
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

def load_key():
    """Load the stored user data from the file."""
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    """Save updated data to the file."""
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    """Generate a key from the passkey for encryption."""
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    """Hash the password using SHA-256 and a salt."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    """Encrypt the text using the provided key."""
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    """Decrypt the encrypted text using the provided key."""
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Load stored user data from the JSON file
stored_data = load_key()

st.title(" 🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome to My 🔐 Data Encryption System Using Streamlit!")
    st.markdown("""
        This app allows you to store encrypted data securely.
        - Register a user with a password.
        - Log in to access encrypted data.
        - Store and retrieve encrypted data using a passkey.
        - Multiple failed login attempts result in temporary lockout.
    """)

elif choice == "Register":
    st.subheader(" ✏️ Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")
    
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Both fields are required.")

elif choice == "Login":
    st.subheader(" 🔑 User Login")
    
    if time.time() < st.session_state.lockout_time:
        remaining_time = int(st.session_state.lockout_time - time.time())
        st.error(f" ⌚ Too many failed attempts. Please wait {remaining_time} seconds.")
        st.stop()
        
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f" ✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f" ❌ Incorrect username or password. {remaining} attempts left.")
            
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("Too many failed attempts. Locked for 60 seconds.")
                st.stop()

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
            st.warning(" 🔓 Please log in first")
    else:
        st.subheader("Retrieve Decrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
        
        if not user_data:
            st.info("No data found for the user.")
        else:
            selected_index = st.selectbox("Select which encrypted data to decrypt", range(len(user_data)))
            selected_encrypted = user_data[selected_index]
            st.code(selected_encrypted)

            passkey_input = st.text_input("Enter passkey to decrypt", type="password")
            if st.button("Decrypt"):
                result = decrypt_text(selected_encrypted, passkey_input)
                if result:
                    st.success(f"✅ Decrypted Data: {result}")
                else:
                    st.error("❌ Decryption failed. Check your passkey.")
