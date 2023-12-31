import streamlit as st
import pickle
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ------------------------- Original to Encrypted -------------------------

st.header("Original to Encrypted")

password = st.text_input("Enter a strong password:", type="password")

uploaded_file = st.file_uploader("Upload an image")

if uploaded_file is not None:
    image_data = uploaded_file.read()

    salt = os.urandom(16)  # Generate a random salt
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    f = Fernet(key)
    encrypted_data = f.encrypt(image_data)

    with open("encrypted_image.pickle", "wb") as f:
        pickle.dump((encrypted_data, salt), f)

    st.success("Image encrypted successfully!")

    st.download_button(
        label="Download Encrypted Image",
        data=encrypted_data,
        file_name="encrypted_image.bin",
        mime="application/octet-stream"
    )

# ------------------------- Encrypted to Original -------------------------

st.header("Encrypted to Original")

password_verify = st.text_input("Enter the password used for encryption:", type="password")

encrypted_file = st.file_uploader("Upload an encrypted image (.bin format)")

if encrypted_file is not None:
    with open("encrypted_image.pickle", "rb") as f:
        encrypted_data_from_file, salt = pickle.load(f)

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    key_from_file = base64.urlsafe_b64encode(kdf.derive(password_verify.encode()))

    f = Fernet(key_from_file)

    try:
        decrypted_data = f.decrypt(encrypted_data_from_file)

        st.success("Image decrypted successfully!")
        st.image(decrypted_data, caption="Decrypted Image")
    except:
        st.error("Invalid password or corrupted image file.")
