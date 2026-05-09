import random
import os
import hashlib
from collections import defaultdict
from PIL import Image, ImageDraw,ImageFont
import subprocess
import sys
from task2_run_acs import aes_cbc_encrypt, aes_cbc_decrypt
from task2_acs import aes_encrypt_block


# =========================
# Core Utility Functions
# =========================

def flip_bit(data, bit_pos):
    """Flip a single bit in a byte string"""
    byte_pos = bit_pos // 8
    bit_in_byte = bit_pos % 8
    data_bytes = bytearray(data)
    data_bytes[byte_pos] ^= (1 << bit_in_byte)
    return bytes(data_bytes)


def hamming_distance(hex1, hex2):
    """Calculate bit differences between two hex strings"""
    bytes1 = bytes.fromhex(hex1)
    bytes2 = bytes.fromhex(hex2)
    return sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(bytes1, bytes2))


def print_blocks(data, block_size=32):
    """Helper to visualize data in blocks"""
    for i in range(0, len(data), block_size):
        print(f"Block {i // block_size + 1}: {data[i:i + block_size]}")


def pad_data(data, block_size=16):
    """PKCS#7 padding"""
    if not data:
        return bytes([block_size] * block_size)
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def unpad_data(data):
    """PKCS#7 unpadding with validation"""
    if not data:
        return b''
    try:
        padding_len = data[-1]
        if padding_len > len(data):
            return data
        if all(b == padding_len for b in data[-padding_len:]):
            return data[:-padding_len]
        return data
    except IndexError:
        return data


# =========================
# Avalanche Effect Analysis
# =========================

def run_avalanche_test():
    """Perform comprehensive avalanche effect testing"""
    results = {
        'plaintext_flips': defaultdict(int),
        'key_flips': defaultdict(int)
    }

    for trial in range(10):
        print(f"\n=== Trial {trial + 1} ===")

        # Generate random inputs
        plaintext = random.randbytes(16)
        key = random.randbytes(16)
        iv = random.randbytes(16)

        print(f"IV: {iv.hex()}")
        print(f"Key: {key.hex()}")
        print(f"Plaintext: {plaintext.hex()}")

        # Original encryption
        original_cipher = aes_cbc_encrypt(plaintext.hex(), key.hex(), iv.hex())
        print("\nOriginal Encryption:")
        print_blocks(original_cipher)

        # Plaintext bit flip test
        flip_pos = random.randint(0, 127)
        flipped_plain = flip_bit(plaintext, flip_pos)
        print(f"\nFlipping bit {flip_pos} in plaintext")
        new_cipher = aes_cbc_encrypt(flipped_plain.hex(), key.hex(), iv.hex())
        diff = hamming_distance(original_cipher, new_cipher)
        results['plaintext_flips'][diff] += 1
        print(f"Bits changed: {diff}")
        print_blocks(new_cipher)

        # Key bit flip test
        flip_pos = random.randint(0, 127)
        flipped_key = flip_bit(key, flip_pos)
        print(f"\nFlipping bit {flip_pos} in key")
        new_cipher = aes_cbc_encrypt(plaintext.hex(), flipped_key.hex(), iv.hex())
        diff = hamming_distance(original_cipher, new_cipher)
        results['key_flips'][diff] += 1
        print(f"Bits changed: {diff}")
        print_blocks(new_cipher)

    return results


def print_avalanche_results(results):
    """Display avalanche test results"""
    print("\n=== Avalanche Effect Summary ===")

    print("\nPlaintext Bit Flips:")
    for bits, count in sorted(results['plaintext_flips'].items()):
        print(f"{bits} bits changed: {count} times")

    print("\nKey Bit Flips:")
    for bits, count in sorted(results['key_flips'].items()):
        print(f"{bits} bits changed: {count} times")

    # Calculate statistics
    plain_bits = list(results['plaintext_flips'].keys())
    key_bits = list(results['key_flips'].keys())

    avg_plain = sum(plain_bits) / len(plain_bits)
    avg_key = sum(key_bits) / len(key_bits)

    std_plain = (sum((b - avg_plain) ** 2 for b in plain_bits) / len(plain_bits)) ** 0.5
    std_key = (sum((b - avg_key) ** 2 for b in key_bits) / len(key_bits)) ** 0.5

    print(f"\nAverage bits changed (plaintext): {avg_plain:.1f} ± {std_plain:.1f}")
    print(f"Average bits changed (key): {avg_key:.1f} ± {std_key:.1f}")
    print(f"Expected ideal: ~64 bits (50%)")


# =========================
# Extended Analysis
# =========================

def error_propagation_test():
    """Test error propagation in CBC mode"""
    print("\n=== Error Propagation Test ===")

    # Fixed test vector
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a" * 2)  # 2 blocks
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    # Original encryption
    ciphertext = aes_cbc_encrypt(plaintext.hex(), key.hex(), iv.hex())
    cipher_blocks = [bytes.fromhex(ciphertext[i:i + 32]) for i in range(0, len(ciphertext), 32)]

    print("\nOriginal Plaintext:")
    print_blocks(plaintext.hex())
    print("\nOriginal Ciphertext:")
    print_blocks(ciphertext)

    # Flip one bit in ciphertext
    flip_pos = random.randint(0, len(cipher_blocks[0]) * 8 - 1)
    corrupted_block = flip_bit(cipher_blocks[0], flip_pos)
    corrupted_cipher = corrupted_block + cipher_blocks[1]

    print(f"\nFlipping bit {flip_pos} in ciphertext block 1")
    print("Corrupted ciphertext:")
    print_blocks(corrupted_cipher.hex())

    # Decrypt corrupted ciphertext
    decrypted = aes_cbc_decrypt(corrupted_cipher.hex(), key.hex(), iv.hex())
    print("\nDecrypted Plaintext with Error:")
    print_blocks(decrypted)

    # Calculate affected blocks
    original_blocks = [plaintext.hex()[i:i + 32] for i in range(0, len(plaintext.hex()), 32)]
    corrupted_blocks = [decrypted[i:i + 32] for i in range(0, len(decrypted), 32)]

    print("\nAffected Blocks Analysis:")
    for i, (orig, corrupt) in enumerate(zip(original_blocks, corrupted_blocks)):
        if orig != corrupt:
            diff = hamming_distance(orig, corrupt)
            print(f"Block {i + 1}: {diff} bits changed ({(diff / 128) * 100:.1f}%)")


def loss_of_block_test():
    """Test effect of losing a ciphertext block"""
    print("\n=== Ciphertext Block Loss Test ===")

    # 4-block plaintext
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a" * 4)
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    # Original encryption
    ciphertext = aes_cbc_encrypt(plaintext.hex(), key.hex(), iv.hex())
    cipher_blocks = [bytes.fromhex(ciphertext[i:i + 32]) for i in range(0, len(ciphertext), 32)]

    print("\nOriginal Plaintext (4 blocks):")
    print_blocks(plaintext.hex())

    # Simulate losing block 2
    corrupted_cipher = cipher_blocks[0] + cipher_blocks[2] + cipher_blocks[3]
    print("\nAfter losing block 2:")
    print_blocks(corrupted_cipher.hex())

    # Decrypt
    decrypted = aes_cbc_decrypt(corrupted_cipher.hex(), key.hex(), iv.hex())
    print("\nDecrypted Plaintext:")
    print_blocks(decrypted)

    # Analysis
    print("\nBlock Corruption Analysis:")
    print("1. Block 1: Correct (used original IV)")
    print("2. Block 2: Corrupted (used missing block as IV)")
    print("3. Block 3: Correct (used block 3 as IV)")
    print("4. Block 4: Unaffected")


def image_encryption_test():
    """Test CBC encryption on black-and-white image with visualization"""
    print("\n=== Black & White Image Encryption Test ===")

    # 1. Create and display original image
    width, height = 32, 32
    img = Image.new('1', (width, height), color=1)  # 1-bit pixels (black and white)

    # Draw a simple pattern
    draw = ImageDraw.Draw(img)
    draw.rectangle((8, 8, 24, 24), fill=0)  # Black rectangle in center
    draw.text((10, 10), "BZU", fill=1)  # White text inside rectangle

    # Save and display original
    img.save("original_bw.bmp")
    print("\nOriginal Image (displaying):")
    img.show(title="Original Image")

    # 2. Prepare image data for encryption
    img_bytes = img.tobytes()
    print(f"\nImage data size: {len(img_bytes)} bytes")
    print("First 16 bytes (hex):", img_bytes[:16].hex())

    # 3. Encrypt using CBC mode
    KEY = "2b7e151628aed2a6abf7158809cf4f3c"  # AES-128 key
    IV = "000102030405060708090a0b0c0d0e0f"  # IV

    print("\nEncrypting image with AES-CBC...")
    ciphertext = aes_cbc_encrypt(img_bytes.hex(), KEY, IV)
    encrypted_bytes = bytes.fromhex(ciphertext)

    # 4. Visualize encrypted data
    print("\nCreating encrypted data visualization...")
    try:
        # Create two visualizations:
        # 1. As grayscale image (shows byte values)
        encrypted_img = Image.frombytes('L', (width, height), encrypted_bytes[:width * height])
        encrypted_img.save("encrypted_cbc.png")

        # 2. As binary image (shows bit patterns)
        bit_array = []
        for byte in encrypted_bytes[:width * height]:
            bit_array.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
        bit_img = Image.new('1', (width * 8, height))
        bit_img.putdata(bit_array)
        bit_img.save("encrypted_cbc_bits.png")

        print("Encrypted visualizations saved:")
        print("- encrypted_cbc.png (byte values)")
        print("- encrypted_cbc_bits.png (bit patterns)")
        encrypted_img.show(title="Encrypted Bytes Visualization")
        bit_img.show(title="Encrypted Bits Visualization")
    except Exception as e:
        print(f"Visualization error: {str(e)}")

    # 5. Decrypt and verify
    print("\nDecrypting image...")
    decrypted_hex = aes_cbc_decrypt(ciphertext, KEY, IV)
    decrypted_bytes = bytes.fromhex(decrypted_hex)[:len(img_bytes)]

    # Reconstruct image
    decrypted_img = Image.frombytes('1', (width, height), decrypted_bytes)
    decrypted_img.save("decrypted_bw.bmp")

    # 6. Verification
    original_hash = hashlib.sha256(img_bytes).hexdigest()
    decrypted_hash = hashlib.sha256(decrypted_bytes).hexdigest()

    print("\n=== Verification Results ===")
    print(f"Original hash: {original_hash}")
    print(f"Decrypted hash: {decrypted_hash}")
    print("MATCH!" if original_hash == decrypted_hash else "MISMATCH!")

    print("\nDecrypted Image (displaying):")
    decrypted_img.show(title="Decrypted Image")


# =========================
# Main Execution
# =========================

if __name__ == "__main__":
    print("=== AES-128 CBC Mode Analysis ===")

    # 1. Avalanche Effect Tests
    print("\nRunning Avalanche Effect Tests...")
    avalanche_results = run_avalanche_test()
    print_avalanche_results(avalanche_results)

    # 2. Error Propagation Tests
    error_propagation_test()

    # 3. Block Loss Tests
    loss_of_block_test()

    # 4. Image Encryption Tests
    image_encryption_test()

