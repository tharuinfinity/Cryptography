from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import os
import time
import psutil

# Generate RSA keys based on the provided key size
def generate_keys(key_len):
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_len,  # Key size (1024, 2048, 3072, 4096)
        backend=default_backend()
    )
    pub_key = priv_key.public_key()
    return priv_key, pub_key

# Encrypt small data chunks using RSA and PKCS1v15 padding
def encrypt_data(data, pub_key):
    return pub_key.encrypt(
        data,
        padding.PKCS1v15()  # Use PKCS1v15 padding
    )

# Decrypt small data chunks using RSA
def decrypt_data(ciphertext, priv_key):
    return priv_key.decrypt(
        ciphertext,
        padding.PKCS1v15()  # Use PKCS1v15 padding
    )

# Encrypt file by splitting it into chunks
def encrypt_file(input_file, pub_key, chunk_size):
    output_file = input_file + ".enc"
    process = psutil.Process(os.getpid())

    cpu_before = process.cpu_percent(interval=None)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break
            enc_chunk = encrypt_data(chunk, pub_key)
            f_out.write(enc_chunk)
    cpu_after = process.cpu_percent(interval=None)
    memory_used = process.memory_info().rss / (1024 * 1024)  # Convert to MB
    print(f"File encrypted: {output_file}")
    print(f"CPU used: {cpu_after - cpu_before}%")
    print(f"Memory used: {memory_used:.2f} MB")
    return output_file

# Decrypt file by splitting it into chunks
def decrypt_file(enc_file, priv_key, chunk_size):
    output_file = enc_file.replace(".enc", ".dec")
    process = psutil.Process(os.getpid())

    cpu_before = process.cpu_percent(interval=None)
    with open(enc_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break
            dec_chunk = decrypt_data(chunk, priv_key)
            f_out.write(dec_chunk)
    cpu_after = process.cpu_percent(interval=None)
    memory_used = process.memory_info().rss / (1024 * 1024)  # Convert to MB
    print(f"File decrypted: {output_file}")
    print(f"CPU used: {cpu_after - cpu_before}%")
    print(f"Memory used: {memory_used:.2f} MB")
    return output_file

# Main function to handle encryption and decryption
def main():
    # Ask whether to encrypt text or file
    option = input("Encrypt (T)ext or (F)ile? (T/F): ").strip().upper()

    # Input key size from user
    key_len = int(input("Enter RSA key size (1024, 2048, 3072, 4096): ").strip())
    
    if key_len not in [1024, 2048, 3072, 4096]:
        print("Invalid key size.")
        return

    # Generate RSA keys
    priv_key, pub_key = generate_keys(key_len)
    print(f"RSA keys generated with {key_len}-bit size.")

    # Set chunk size based on key size
    chunk_size = (key_len // 8) - 11  # Data chunk size for encryption
    ciphertext_size = key_len // 8  # Ciphertext chunk size

    if option == 'T':
        # Input text for encryption
        message = input("Enter text to encrypt: ").encode('utf-8')

        # Encrypt message and calculate CPU/Memory usage
        start = time.time()
        process = psutil.Process(os.getpid())
        cpu_before = process.cpu_percent(interval=None)
        ciphertext = encrypt_data(message, pub_key)
        enc_time = time.time() - start
        cpu_after = process.cpu_percent(interval=None)
        memory_used = process.memory_info().rss / (1024 * 1024)
        print(f"Encryption took {enc_time:.6f} seconds.")
        print(f"CPU used: {cpu_after - cpu_before}%")
        print(f"Memory used: {memory_used:.2f} MB")

        # Decrypt the message and check CPU/Memory usage
        start = time.time()
        cpu_before = process.cpu_percent(interval=None)
        decrypted_msg = decrypt_data(ciphertext, priv_key)
        dec_time = time.time() - start
        cpu_after = process.cpu_percent(interval=None)
        memory_used = process.memory_info().rss / (1024 * 1024)
        print(f"Decryption took {dec_time:.6f} seconds.")
        print(f"CPU used: {cpu_after - cpu_before}%")
        print(f"Memory used: {memory_used:.2f} MB")

        print(f"Decrypted message: {decrypted_msg.decode('utf-8')}")

    elif option == 'F':
        # Input file path
        file_path = input("Enter the file path: ").strip()

        if not os.path.exists(file_path):
            print("File not found.")
            return
        
        # Encrypt file
        start = time.time()
        enc_file = encrypt_file(file_path, pub_key, chunk_size)
        enc_time = time.time() - start
        print(f"File encryption took {enc_time:.6f} seconds.")

        # Decrypt file
        start = time.time()
        dec_file = decrypt_file(enc_file, priv_key, ciphertext_size)
        dec_time = time.time() - start
        print(f"File decryption took {dec_time:.6f} seconds.")

if __name__ == "__main__":
    main()
