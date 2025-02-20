from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import psutil
import time
import binascii
import os

# Function to handle AES encryption
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)  # Securely generate a random IV (16 bytes)

    # Padding the plaintext to 16-byte block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Create AES cipher object with key and IV in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext  # Return IV + ciphertext

# Function to handle AES decryption
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]  # Extract the IV from the beginning
    ciphertext = ciphertext[16:]  # The rest is the actual ciphertext

    # Create AES cipher object with key and IV in CBC mode
    cipher_dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher_dec.decryptor()

    # Decrypt data
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpadding the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data

# Function to get CPU and memory usage
def get_performance_metrics():
    cpu_usage = psutil.cpu_percent(interval=None)
    memory_info = psutil.virtual_memory()
    memory_usage = memory_info.used / (1024 ** 2)  # Convert to MB
    return cpu_usage, memory_usage

# Function to read file content
def read_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

# Function to write file content
def write_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

# Define key as variable, or allow the user to input it
key_hex = input("Enter a key in hexadecimal (32, 48, or 64 characters): ")

try:
    # Convert key from hex to bytes
    key = binascii.unhexlify(key_hex)

    # Check if the key length is valid (16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes (32, 48, or 64 hex characters) for AES-128, AES-192, or AES-256.")

    # User input: choose whether to encrypt or decrypt
    choice = input("Do you want to (1) Encrypt text, (2) Decrypt text, (3) Encrypt file, or (4) Decrypt file? Enter 1, 2, 3, or 4: ")

    if choice == '1':  # Encrypt text
        plaintext = input("Enter the message you want to encrypt: ").encode()

        # Measure performance before encryption
        cpu_before, memory_before = get_performance_metrics()

        # Start encryption timer
        start_time = time.time()

        # Perform AES encryption
        ciphertext = aes_encrypt(plaintext, key)
        
        # End encryption timer
        encryption_time = time.time() - start_time

        # Measure performance after encryption
        cpu_after, memory_after = get_performance_metrics()

        print(f"Ciphertext (in hex): {ciphertext.hex()}")
        print(f"Encryption time: {encryption_time:.6f} seconds")
        print(f"CPU Usage Before: {cpu_before}% | After: {cpu_after}%")
        print(f"Memory Usage Before: {memory_before:.2f} MB | After: {memory_after:.2f} MB")

    elif choice == '2':  # Decrypt text
        ciphertext_hex = input("Enter the ciphertext (in hex) you want to decrypt: ")
        
        # Convert hex string back to bytes
        ciphertext = bytes.fromhex(ciphertext_hex)

        # Measure performance before decryption
        cpu_before, memory_before = get_performance_metrics()

        # Start decryption timer
        start_time = time.time()

        # Perform AES decryption
        decrypted_data = aes_decrypt(ciphertext, key)

        # End decryption timer
        decryption_time = time.time() - start_time

        # Measure performance after decryption
        cpu_after, memory_after = get_performance_metrics()

        try:
            decrypted_data_text = decrypted_data.decode('utf-8')
            print(f"Decrypted Data: {decrypted_data_text}")
        except UnicodeDecodeError:
            print("Decryption succeeded, but the result is not valid UTF-8 text. Showing hex representation instead.")
            print(f"Decrypted Data (in hex): {decrypted_data.hex()}")

        print(f"Decryption time: {decryption_time:.6f} seconds")
        print(f"CPU Usage Before: {cpu_before}% | After: {cpu_after}%")
        print(f"Memory Usage Before: {memory_before:.2f} MB | After: {memory_after:.2f} MB")

    elif choice == '3':  # Encrypt file
        file_path = input("Enter the path of the file you want to encrypt: ")
        file_data = read_file(file_path)

        # Measure performance before encryption
        cpu_before, memory_before = get_performance_metrics()

        # Start encryption timer
        start_time = time.time()

        # Perform AES encryption
        ciphertext = aes_encrypt(file_data, key)
        
        # End encryption timer
        encryption_time = time.time() - start_time

        # Measure performance after encryption
        cpu_after, memory_after = get_performance_metrics()

        encrypted_file_path = file_path + ".enc"
        write_file(encrypted_file_path, ciphertext)

        print(f"File encrypted successfully. Encrypted file saved as: {encrypted_file_path}")
        print(f"Encryption time: {encryption_time:.6f} seconds")
        print(f"CPU Usage Before: {cpu_before}% | After: {cpu_after}%")
        print(f"Memory Usage Before: {memory_before:.2f} MB | After: {memory_after:.2f} MB")

    elif choice == '4':  # Decrypt file
        file_path = input("Enter the path of the file you want to decrypt: ")
        ciphertext = read_file(file_path)

        # Measure performance before decryption
        cpu_before, memory_before = get_performance_metrics()

        # Start decryption timer
        start_time = time.time()

        # Perform AES decryption
        decrypted_data = aes_decrypt(ciphertext, key)

        # End decryption timer
        decryption_time = time.time() - start_time

        # Measure performance after decryption
        cpu_after, memory_after = get_performance_metrics()

        decrypted_file_path = file_path.replace(".enc", ".dec")
        write_file(decrypted_file_path, decrypted_data)

        print(f"File decrypted successfully. Decrypted file saved as: {decrypted_file_path}")
        print(f"Decryption time: {decryption_time:.6f} seconds")
        print(f"CPU Usage Before: {cpu_before}% | After: {cpu_after}%")
        print(f"Memory Usage Before: {memory_before:.2f} MB | After: {memory_after:.2f} MB")

    else:
        print("Invalid choice. Please enter 1 for Encrypt text, 2 for Decrypt text, 3 for Encrypt file, or 4 for Decrypt file.")

except (binascii.Error, ValueError) as e:
    print(f"Error: {str(e)}. Please provide a valid key in hexadecimal format.")
