import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key for encryption
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # Format: {"encrypted_text": {"encrypted_text": ..., "passkey": ...}}
failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    data_entry = stored_data.get(encrypted_text)
    if data_entry and data_entry["passkey"] == hashed_passkey:
        failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        failed_attempts += 1
        return None

# Streamlit UI
st.set_page_config(page_title="Secure Data Encryption System", layout="centered")
st.title("🔐 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Use this application to securely store and retrieve your data using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📥 Store Data")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted_text, language='text')
        else:
            st.error("⚠️ Please provide both data and a passkey.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            if decrypted_text:
                st.success("✅ Decrypted Data:")
                st.code(decrypted_text, language='text')
            else:
                attempts_left = 3 - failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please provide both encrypted data and a passkey.")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Replace with secure authentication in production
            failed_attempts = 0
            st.success("✅ Reauthorized successfully! You can now attempt decryption again.")
        else:
            st.error("❌ Incorrect master password.")
