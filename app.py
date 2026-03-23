import streamlit as st
from crypto_utils import encrypt_file, decrypt_file
from auth import register, login

st.title("🔐 Secure File Vault")

menu = st.sidebar.selectbox("Menu", ["Register", "Login", "Encrypt File", "Decrypt File"])

if menu == "Register":
    st.subheader("Create Account")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")
    if st.button("Register"):
        register(u,p)
        st.success("Account Created!")

elif menu == "Login":
    st.subheader("Login")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")
    if st.button("Login"):
        if login(u,p):
            st.success("Login Successful!")
        else:
            st.error("Invalid Credentials")

elif menu == "Encrypt File":
    st.subheader("Encrypt Your File")
    file = st.file_uploader("Upload File")
    password = st.text_input("Enter Secret Password", type="password")

    if file and password:
        encrypted = encrypt_file(file.read(), password)
        st.download_button("Download Encrypted File", encrypted, "encrypted.bin")
        st.success("File Encrypted Successfully!")

elif menu == "Decrypt File":
    st.subheader("Decrypt Your File")
    file = st.file_uploader("Upload Encrypted File")
    password = st.text_input("Enter Secret Password", type="password")

    if file and password:
        try:
            decrypted = decrypt_file(file.read(), password)
            st.download_button("Download Decrypted File", decrypted, "decrypted_file")
            st.success("File Decrypted Successfully!")
        except:
            st.error("Wrong Password or Corrupted File!")
