from Crypto.Util.Padding import pad, unpad
from task2_acs import aes_encrypt_block, aes_decrypt_block


def pad_to_exact_size(data, target_size):

    padding_needed = target_size - len(data)
    if padding_needed <= 0:
        return data  # Already at or exceeds target size

    # Create padding bytes (each byte equals padding length)
    padding = bytes([padding_needed] * padding_needed)
    return data + padding


def validate_and_unpad(data):

    if not data:
        return data

    padding_len = data[-1]

    # Validate padding structure
    if padding_len > len(data) or not all(b == padding_len for b in data[-padding_len:]):
        return data  # Return unchanged if padding is suspect

    return data[:-padding_len]  # Remove valid padding


def aes_cbc_encrypt(plaintext_hex, key_hex, iv_hex):

    try:
        # Convert hex strings to bytes
        plaintext = bytes.fromhex(plaintext_hex)
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)


        # Calculate required blocks (16 bytes each)
        block_count = max(1, (len(plaintext) + 15) // 16)
        target_size = block_count * 16


        # Apply PKCS#7 padding
        padded_data = pad_to_exact_size(plaintext, target_size)

        # CBC Encryption Process
        ciphertext = b''
        previous_block = iv  # Start with IV for first block

        for block_num in range(block_count):
            start = block_num * 16
            block = padded_data[start:start + 16]

            print(f"\nBlock {block_num + 1}:")
            print(f"Plaintext: {block.hex()}")
            print(f"Previous:  {previous_block.hex()}")

            # CBC magic happens here
            xor_result = bytes(a ^ b for a, b in zip(block, previous_block))
            encrypted_block = aes_encrypt_block(xor_result, key)

            ciphertext += encrypted_block
            previous_block = encrypted_block  # For next iteration

            print(f"XOR result: {xor_result.hex()}")
            print(f"Encrypted:  {encrypted_block.hex()}")

        print("\nFinal ciphertext:", ciphertext.hex())
        return ciphertext.hex()

    except Exception as e:
        print(f"Encryption failed: {str(e)}")
        return ""


def aes_cbc_decrypt(ciphertext_hex, key_hex, iv_hex):

    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)

        # Basic validation
        if len(ciphertext) % 16 != 0:
            print("Error: Ciphertext must be multiple of 16 bytes")
            return ""

        plaintext = b''
        previous_cipher_block = iv

        # Process each 16-byte block
        for block_num in range(len(ciphertext) // 16):
            start = block_num * 16
            block = ciphertext[start:start + 16]

            print(f"\nBlock {block_num + 1}:")
            print(f"Ciphertext: {block.hex()}")

            # Core decryption steps
            decrypted = aes_decrypt_block(block, key)
            plaintext_block = bytes(a ^ b for a, b in zip(decrypted, previous_cipher_block))

            plaintext += plaintext_block
            previous_cipher_block = block  # Critical for CBC mode

            print(f"Decrypted:  {decrypted.hex()}")

        # Safely remove padding
        clean_plaintext = validate_and_unpad(plaintext)
        return clean_plaintext.hex()

    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return ""


def main():
    """Interactive CLI for AES-CBC operations"""
    print("AES-CBC Encryption/Decryption Tool")

    while True:
        choice = input("\nEncrypt (E) or Decrypt (D)? ").upper()

        if choice == 'E':
            print("\nEncryption Mode")
            plaintext = input("Enter plaintext (hex): ").strip()
            key = input("Enter 128-bit key (32 hex chars): ").strip()
            iv = input("Enter 128-bit IV (32 hex chars): ").strip()

            if len(key) != 32 or len(iv) != 32:
                print("Error: Key and IV must be 32 hex characters (128 bits)")
                continue

            result = aes_cbc_encrypt(plaintext, key, iv)


        elif choice == 'D':
            print("\nDecryption Mode")
            ciphertext = input("Enter ciphertext (hex): ").strip()
            key = input("Enter 128-bit key (32 hex chars): ").strip()
            iv = input("Enter 128-bit IV (32 hex chars): ").strip()

            if len(key) != 32 or len(iv) != 32:
                print("Error: Key and IV must be 32 hex characters (128 bits)")
                continue

            result = aes_cbc_decrypt(ciphertext, key, iv)


        else:
            print("Invalid choice. Please enter E or D.")


if __name__ == "__main__":
    main()