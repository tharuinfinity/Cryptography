import hashlib  # Import hash library
import hmac  # Import HMAC for keyed hashing
from concurrent.futures import ThreadPoolExecutor  # Import the function for parallel processing
import time  # Import the function time
import psutil  # Import psutil for CPU and memory usage tracking
import os  # Import os to get the current process ID

# HMAC hashing function for a single chunk
def hmac_sha256_hash_chunk(key, data_chunk):
    return hmac.new(key, data_chunk, hashlib.sha256).digest()

# Parallel HMAC-SHA256 hashing function
def hmac_sha256_parallel(data, key, chunk_size=1024*1024):  # Split the data into 1 MB chunks
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda chunk: hmac_sha256_hash_chunk(key, chunk), chunks))
    
    # Combine all HMAC results into one final HMAC-SHA256 hash
    final_hmac = hmac.new(key, b'', hashlib.sha256)
    for chunk_digest in results:
        final_hmac.update(chunk_digest)
    
    return final_hmac.hexdigest()

# Function to measure CPU and memory usage
def get_cpu_memory_usage():
    process = psutil.Process(os.getpid())
    cpu_usage = psutil.cpu_percent(interval=None)  # CPU usage percentage
    memory_usage = process.memory_info().rss / (1024 * 1024)  # Memory usage in MB
    return cpu_usage, memory_usage

# Function to get user-defined key based on selected size
def get_key_from_user(key_size):
    while True:
        key_hex = input(f"Enter a key of {key_size} bits in hexadecimal format (should be {key_size//8 * 2} hex characters): ")
        if len(key_hex) == key_size // 4:  # Each hex character represents 4 bits
            return bytes.fromhex(key_hex)
        else:
            print(f"Invalid key length! The key must be {key_size//8 * 2} hex characters long.")

# Function to hash a file using HMAC-SHA256
def hmac_sha256_file(file_path, key, chunk_size=1024*1024):
    final_hmac = hmac.new(key, b'', hashlib.sha256)
    
    # Read and process file in chunks
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            final_hmac.update(chunk)

    return final_hmac.hexdigest()

def main():
    print("Do you want to hash (1) a Text message or (2) a File?")
    input_choice = input("Enter 1 for Text or 2 for File: ")

    # Step 1: Choose a key size
    print("Select key size (in bits):")
    print("1. 128-bit (16 bytes)")
    print("2. 192-bit (24 bytes)")
    print("3. 256-bit (32 bytes)")
    
    key_size_choice = input("Enter your choice (1, 2, or 3): ")

    # Step 2: Set the key size based on user choice
    if key_size_choice == '1':
        key_size = 128
    elif key_size_choice == '2':
        key_size = 192
    elif key_size_choice == '3':
        key_size = 256
    else:
        print("Invalid choice. Defaulting to 256-bit key.")
        key_size = 256

    # Step 3: Get the key from user based on selected key size
    key = get_key_from_user(key_size)

    # Hash text or file based on user input
    if input_choice == '1':
        # Text input
        message = input("Enter the message to hash: ")
        data = message.encode('utf-8')  # Convert the input message to bytes (UTF-8)

        # Track initial CPU and memory usage
        initial_cpu, initial_memory = get_cpu_memory_usage()

        # Measure the time for final hashing
        start_time = time.perf_counter()
        hash_value = hmac_sha256_parallel(data, key)
        hash_time = time.perf_counter() - start_time
        
        # Track CPU and memory usage after hashing
        final_cpu, final_memory = get_cpu_memory_usage()

        print(f"HMAC-SHA-256 Hash (Text): {hash_value}")
        print(f"Hashing time: {hash_time:.6f} seconds")
        print(f"CPU usage during hashing: {final_cpu - initial_cpu:.2f}%")
        print(f"Memory usage during hashing: {final_memory - initial_memory:.2f} MB")

    elif input_choice == '2':
        # File input
        file_path = input("Enter the file path to hash: ")
        if not os.path.isfile(file_path):
            print(f"Error: File '{file_path}' does not exist.")
            return

        # Track initial CPU and memory usage
        initial_cpu, initial_memory = get_cpu_memory_usage()

        # Measure the time for file hashing
        start_time = time.perf_counter()
        hash_value = hmac_sha256_file(file_path, key)
        hash_time = time.perf_counter() - start_time

        # Track CPU and memory usage after hashing
        final_cpu, final_memory = get_cpu_memory_usage()

        print(f"HMAC-SHA-256 Hash (File): {hash_value}")
        print(f"Hashing time: {hash_time:.6f} seconds")
        print(f"CPU usage during hashing: {final_cpu - initial_cpu:.2f}%")
        print(f"Memory usage during hashing: {final_memory - initial_memory:.2f} MB")

    else:
        print("Invalid choice. Please enter 1 for Text or 2 for File.")

if __name__ == "__main__":
    main()
