from Crypto.Cipher import AES

master_password = "hi"  # replace with actual master password

# hash the master password with itself, using aes256
master_password_bytes = master_password.encode("utf-8")
master_password_bytes_len = len(master_password_bytes)

ciphertext = (
    len(master_password_bytes).to_bytes(8, byteorder="big") + master_password_bytes
)

if len(master_password_bytes) < 32:
    master_password_bytes += b"\0" * (32 - len(master_password_bytes))

if len(ciphertext) % 16 != 0:
    ciphertext += b"\0" * (16 - len(ciphertext) % 16)

cipher = AES.new(master_password_bytes, AES.MODE_ECB)
encrypted_master_password = cipher.encrypt(ciphertext)

filename = "master_pw"
with open(filename, "wb") as f:
    f.write(encrypted_master_password)
