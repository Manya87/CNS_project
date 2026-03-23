from __future__ import annotations

from pathlib import Path

import streamlit as st

from auth import authenticate_user, register_user
from crypto_utils import decrypt_data, encrypt_data

st.set_page_config(page_title="Secure File Vault", page_icon="??", layout="centered")


def init_session_state() -> None:
    defaults = {
        "logged_in": False,
        "username": "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def render_header() -> None:
    st.title("?? Secure File Vault")
    st.caption("Upload, encrypt, decrypt, and safely download your files.")


def auth_view() -> None:
    st.subheader("User Authentication")
    tab_login, tab_register = st.tabs(["Login", "Register"])

    with tab_login:
        login_user = st.text_input("Username", key="login_user")
        login_pass = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login", type="primary", use_container_width=True):
            success, message = authenticate_user(login_user, login_pass)
            if success:
                st.session_state.logged_in = True
                st.session_state.username = login_user.strip()
                st.success(message)
            else:
                st.error(message)

    with tab_register:
        reg_user = st.text_input("New username", key="reg_user")
        reg_pass = st.text_input("New password", type="password", key="reg_pass")
        if st.button("Create Account", use_container_width=True):
            success, message = register_user(reg_user, reg_pass)
            if success:
                st.success(message)
            else:
                st.error(message)


def encrypt_view() -> None:
    st.subheader("Encrypt File")
    uploaded_file = st.file_uploader("Upload a file to encrypt", type=None)

    secret_key = st.text_input(
        "Enter encryption secret key",
        type="password",
        help="Use a strong key. Keep it safe; you need it for decryption.",
    )

    if uploaded_file and st.button("Encrypt File", type="primary", use_container_width=True):
        try:
            original_data = uploaded_file.read()
            encrypted = encrypt_data(original_data, secret_key)
            encrypted_name = f"{Path(uploaded_file.name).name}.sfv"
            st.success("File encrypted successfully.")
            st.download_button(
                label="Download Encrypted File",
                data=encrypted,
                file_name=encrypted_name,
                mime="application/octet-stream",
                use_container_width=True,
            )
        except Exception as exc:
            st.error(str(exc))


def decrypt_view() -> None:
    st.subheader("Decrypt File")
    encrypted_file = st.file_uploader(
        "Upload an encrypted .sfv file",
        type=["sfv", "bin", "enc"],
        key="encrypted_uploader",
    )
    secret_key = st.text_input(
        "Enter decryption secret key",
        type="password",
        key="decrypt_key",
    )

    if encrypted_file and st.button("Decrypt File", type="primary", use_container_width=True):
        try:
            encrypted_bytes = encrypted_file.read()
            decrypted = decrypt_data(encrypted_bytes, secret_key)
            base_name = Path(encrypted_file.name).name
            if base_name.endswith(".sfv"):
                base_name = base_name[:-4]
            out_name = f"decrypted_{base_name}"
            st.success("File decrypted successfully.")
            st.download_button(
                label="Download Decrypted File",
                data=decrypted,
                file_name=out_name,
                mime="application/octet-stream",
                use_container_width=True,
            )
        except Exception as exc:
            st.error(str(exc))


def main() -> None:
    init_session_state()
    render_header()

    with st.sidebar:
        st.header("Navigation")
        page = st.radio(
            "Go to",
            ["Authentication", "Encrypt File", "Decrypt File"],
        )

        if st.session_state.logged_in:
            st.success(f"Logged in as {st.session_state.username}")
            if st.button("Logout", use_container_width=True):
                st.session_state.logged_in = False
                st.session_state.username = ""
                st.info("Logged out.")

    if page == "Authentication":
        auth_view()
        return

    if not st.session_state.logged_in:
        st.warning("Please log in first from the Authentication page.")
        return

    if page == "Encrypt File":
        encrypt_view()
    else:
        decrypt_view()


if __name__ == "__main__":
    main()
