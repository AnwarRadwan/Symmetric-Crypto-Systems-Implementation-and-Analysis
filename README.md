# AES-128 Implementation and Cryptographic Analysis

This project is a Python implementation of the Advanced Encryption Standard (AES-128) as part of a Cryptography course. It includes the core algorithm implementation, along with an analysis of security properties such as the Avalanche Effect and error propagation in Cipher Block Chaining (CBC) mode.

## Project Files

1.  **`task2_acs.py`**:
    *   Contains the core AES operations:
        *   Galois Field (GF(2⁸)) arithmetic.
        *   S-box generation and Affine Transformation.
        *   `SubBytes`, `ShiftRows`, `MixColumns`, and `AddRoundKey` transformations.
        *   11-round Key Expansion schedule.
        *   Single-block encryption and decryption.

2.  **`task2_run_acs.py`**:
    *   Implementation of **CBC (Cipher Block Chaining)** mode.
    *   Hexadecimal string handling for inputs and outputs.
    *   Encryption and decryption functions for long data strings.

3.  **`task2_acs_avalanche_analysis.py`**:
    *   Comprehensive analysis script:
        *   **Avalanche Effect Test**: Measures how much the ciphertext changes when a single bit is flipped in the plaintext or key.
        *   **Error Propagation Test**: Studies the impact of a single-bit error in the ciphertext on the decryption process in CBC mode.
        *   **Block Loss Test**: Analyzes the consequences of losing an entire ciphertext block.
        *   **Image Encryption**: Demonstrates encrypting a black-and-white image and visualizes the results.

4.  **`Report.pdf`**: Detailed project report and experimental results.

## Requirements

*   Python 3.x
*   `Pillow` library (for image processing in the analysis script):
    ```bash
    pip install Pillow
    ```

## Usage

### 1. Run Comprehensive Analysis:
To execute all tests (Avalanche, Error Propagation, Image Encryption), run:
```bash
python task2_acs_avalanche_analysis.py
```

### 2. Basic Encryption/Decryption:
You can use the functions in `task2_run_acs.py` to encrypt or decrypt specific hex strings programmatically.

## Contributors
*   **1221808**
*   **1221082**
*   **1222275**

---
*This project was developed for educational purposes for the ENCS4320 course.*

