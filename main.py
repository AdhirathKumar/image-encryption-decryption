import streamlit as st
import pickle
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64  # Added for base64 encoding

# ------------------------- Original to Encrypted -------------------------

st.header("Original to Encrypted")

password = st.text_input("Enter a strong password:", type="password")

uploaded_file = st.file_uploader("Upload an image")

if uploaded_file is not None:
    image_data = uploaded_file.read()

    salt = os.urandom(16)  # Generate a random salt
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))[
        :32
    ]  # Extract 32 bytes

    backend = default_backend()
    iv = os.urandom(16)  # Generate a random initialization vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(image_data) + encryptor.finalize()

    with open("encrypted_image.pickle", "wb") as f:
        pickle.dump((encrypted_data, iv, salt), f)  # Store IV and salt

    st.success("Image encrypted successfully!")

    st.download_button(
        label="Download Encrypted Image",
        data=encrypted_data,
        file_name="encrypted_image.bin",
        mime="application/octet-stream",
    )

# ------------------------- Encrypted to Original -------------------------

st.header("Encrypted to Original")

password_verify = st.text_input(
    "Enter the password used for encryption:", type="password"
)

encrypted_file = st.file_uploader("Upload an encrypted image (.bin format)")

if encrypted_file is not None:
    with open("encrypted_image.pickle", "rb") as f:
        encrypted_data_from_file, iv, salt = pickle.load(f)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=backend,
    )
    key_from_file = base64.urlsafe_b64encode(kdf.derive(password_verify.encode()))[:32]

    cipher = Cipher(algorithms.AES(key_from_file), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    try:
        decrypted_data = (
            decryptor.update(encrypted_data_from_file) + decryptor.finalize()
        )

        st.success("Image decrypted successfully!")
        st.image(decrypted_data, caption="Decrypted Image")
    except:
        st.error("Invalid password or corrupted image file.")
