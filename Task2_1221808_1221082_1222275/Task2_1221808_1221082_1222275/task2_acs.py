# ==============================================
# Galois Field Arithmetic (GF(2⁸)) Operations
# ==============================================

def gf_add(a, b):
    """Simple XOR addition in GF(2⁸)"""
    return a ^ b


def gf_mul(a, b):
    """
    Multiply two numbers in GF(2⁸) modulo AES irreducible polynomial.
    Implements 'peasant's algorithm' for efficient multiplication.
    """
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a <<= 1
        if carry:
            a ^= 0x11B  # AES polynomial: x⁸ + x⁴ + x³ + x + 1
        b >>= 1
    return p


def gf_inverse(a):
    """
    Find multiplicative inverse in GF(2⁸) using Extended Euclidean Algorithm.
    Returns 0 for input 0 (which has no inverse).
    """
    if a == 0:
        return 0

    # Initialize algorithm variables
    old_r, r = 0x11B, a  # AES polynomial and our input
    old_s, s = 0, 1

    while r != 0:
        # Compute how much we need to shift
        degree_diff = (old_r.bit_length() - 1) - (r.bit_length() - 1)
        if degree_diff < 0:
            old_r, r = r, old_r
            old_s, s = s, old_s
            continue

        # Polynomial division via shifting and XOR
        shifted_r = r << degree_diff
        old_r ^= shifted_r
        old_s ^= (s << degree_diff)

    return old_s & 0xFF  # Return only the byte we need


# ==============================================
# AES Core Transformations
# ==============================================

def sub_bytes(state):
    """Apply S-box substitution to each byte in state"""
    for i in range(4):
        for j in range(4):
            state[i][j] = s_box_transform(state[i][j])


def s_box_transform(byte):
    """
    Compute AES S-box value for a byte through:
    1. Multiplicative inverse in GF(2⁸)
    2. Affine transformation
    """
    if byte == 0:
        return 0x63  # Special case for zero

    inv = gf_inverse(byte)

    # Apply affine transformation
    transformed = 0
    for i in range(8):
        # This implements the AES affine transform matrix
        bit = ((inv >> i) ^
               (inv >> ((i + 4) % 8)) ^
               (inv >> ((i + 5) % 8)) ^
               (inv >> ((i + 6) % 8)) ^
               (inv >> ((i + 7) % 8)) ^
               (0x63 >> i)) & 1
        transformed |= (bit << i)

    return transformed


def shift_rows(state):
    """Rotate each row left by its index (0-3)"""
    state[1] = state[1][1:] + state[1][:1]  # Row 1: 1 byte left
    state[2] = state[2][2:] + state[2][:2]  # Row 2: 2 bytes left
    state[3] = state[3][3:] + state[3][:3]  # Row 3: 3 bytes left


def mix_columns(state):
    """Diffuse bytes through column mixing using GF(2⁸) multiplication"""
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        # Each new byte is a specific mix of the original column bytes
        state[0][i] = gf_mul(0x02, col[0]) ^ gf_mul(0x03, col[1]) ^ col[2] ^ col[3]
        state[1][i] = col[0] ^ gf_mul(0x02, col[1]) ^ gf_mul(0x03, col[2]) ^ col[3]
        state[2][i] = col[0] ^ col[1] ^ gf_mul(0x02, col[2]) ^ gf_mul(0x03, col[3])
        state[3][i] = gf_mul(0x03, col[0]) ^ col[1] ^ col[2] ^ gf_mul(0x02, col[3])


def add_round_key(state, round_key):
    """XOR state with round key"""
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]


# ==============================================
# Key Expansion
# ==============================================

def key_expansion(key):
    """
    Expand 128-bit key into 11 round keys (44 words).
    Implements AES key schedule algorithm.
    """
    # Round constants for key expansion
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    # Initialize key schedule
    round_keys_words = [0] * 44

    # First 4 words come directly from the key
    for i in range(4):
        round_keys_words[i] = (
                (key[4 * i] << 24) |
                (key[4 * i + 1] << 16) |
                (key[4 * i + 2] << 8) |
                key[4 * i + 3]
        )

    # Generate remaining words
    for i in range(4, 44):
        temp = round_keys_words[i - 1]

        if i % 4 == 0:
            # Apply key schedule core
            temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF  # RotWord
            # SubWord
            temp_bytes = [(temp >> (24 - 8 * j)) & 0xFF for j in range(4)]
            temp_bytes = [s_box_transform(b) for b in temp_bytes]
            temp = (temp_bytes[0] << 24) | (temp_bytes[1] << 16) | (temp_bytes[2] << 8) | temp_bytes[3]
            temp ^= (RCON[i // 4 - 1] << 24)

        round_keys_words[i] = round_keys_words[i - 4] ^ temp

    # Convert to 4x4 matrices for each round
    round_keys = []
    for round in range(11):
        key_matrix = [[0] * 4 for _ in range(4)]
        for col in range(4):
            word = round_keys_words[4 * round + col]
            key_matrix[0][col] = (word >> 24) & 0xFF
            key_matrix[1][col] = (word >> 16) & 0xFF
            key_matrix[2][col] = (word >> 8) & 0xFF
            key_matrix[3][col] = word & 0xFF
        round_keys.append(key_matrix)

    return round_keys


# ==============================================
# Inverse Transformations for Decryption
# ==============================================

def inv_sub_bytes(state):
    """Inverse byte substitution using inverse S-box"""
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_s_box_transform(state[i][j])


def inv_s_box_transform(byte):
    """Reverse of the S-box transformation"""
    # First undo the affine transform
    inv_affine = 0
    for bit in range(8):
        inv_affine ^= ((byte >> ((bit + 2) % 8)) ^
                       (byte >> ((bit + 5) % 8)) ^
                       (byte >> ((bit + 7) % 8)) ^
                       0x05) & 1
        inv_affine <<= 1
    inv_affine >>= 1

    # Then take the multiplicative inverse
    return gf_inverse(inv_affine)


def inv_shift_rows(state):
    """Reverse row shifting - rotate right instead of left"""
    state[1] = state[1][3:] + state[1][:3]  # 1 byte right
    state[2] = state[2][2:] + state[2][:2]  # 2 bytes right
    state[3] = state[3][1:] + state[3][:1]  # 3 bytes right


def inv_mix_columns(state):
    """Inverse column mixing operation"""
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        # Different coefficients for inverse operation
        state[0][i] = gf_mul(0x0e, col[0]) ^ gf_mul(0x0b, col[1]) ^ gf_mul(0x0d, col[2]) ^ gf_mul(0x09, col[3])
        state[1][i] = gf_mul(0x09, col[0]) ^ gf_mul(0x0e, col[1]) ^ gf_mul(0x0b, col[2]) ^ gf_mul(0x0d, col[3])
        state[2][i] = gf_mul(0x0d, col[0]) ^ gf_mul(0x09, col[1]) ^ gf_mul(0x0e, col[2]) ^ gf_mul(0x0b, col[3])
        state[3][i] = gf_mul(0x0b, col[0]) ^ gf_mul(0x0d, col[1]) ^ gf_mul(0x09, col[2]) ^ gf_mul(0x0e, col[3])


# ==============================================
# Block Encryption/Decryption
# ==============================================

def aes_encrypt_block(block, key):
    """Encrypt a single 128-bit block using AES-128"""
    # Initialize state matrix
    state = [[block[i * 4 + j] for j in range(4)] for i in range(4)]
    round_keys = key_expansion(key)

    # Initial round
    add_round_key(state, round_keys[0])

    # 9 main rounds
    for round_num in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_num])

    # Final round (no mix_columns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])

    # Flatten state to bytes
    return bytes([state[i][j] for i in range(4) for j in range(4)])


def aes_decrypt_block(block, key):
    """Decrypt a single 128-bit block using AES-128"""
    state = [[block[i * 4 + j] for j in range(4)] for i in range(4)]
    round_keys = key_expansion(key)

    # Initial round
    add_round_key(state, round_keys[10])
    inv_shift_rows(state)
    inv_sub_bytes(state)

    # 9 main rounds
    for round_num in range(9, 0, -1):
        add_round_key(state, round_keys[round_num])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    # Final round
    add_round_key(state, round_keys[0])

    return bytes([state[i][j] for i in range(4) for j in range(4)])

