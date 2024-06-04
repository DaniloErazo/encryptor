# EncryptorService README

## Overview

The `EncryptorService` is a Spring Boot service that provides functionality to encrypt and decrypt files using the AES-CBC encryption algorithm. The service leverages password-based encryption, ensuring secure file handling by generating encryption keys derived from user-provided passwords. This README explains the implementation details, the challenges faced during development, and the conclusions drawn.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Implementation Details](#implementation-details)
   - [Encryption Process](#encryption-process)
   - [Decryption Process](#decryption-process)
   - [Key Generation](#key-generation)
   - [SHA-256 Hashing](#sha-256-hashing)
3. [Technology Used](#technology-used)
4. [Challenges](#challenges)
5. [Conclusions](#conclusions)

## Getting Started

### Prerequisites

- Java 8 or higher
- Spring Boot
- Maven or Gradle

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/DaniloErazo/encryptor.git
   cd encryptor-service
   ```

2. Build the project:
   ```bash
   mvn clean install
   ```

3. Run the application:
   ```bash
   mvn spring-boot:run
   ```

## Implementation Details

### Encryption Process

The encryption process involves the following steps:

1. **Generate Salt**: A random salt is generated using `SecureRandom`.
2. **Generate Key**: A key is derived from the user-provided password and the generated salt using the PBKDF2 with HMAC SHA-256 algorithm.
3. **Initialize Cipher**: The AES-CBC cipher is initialized in encryption mode with the derived key and a randomly generated IV.
4. **Compute Hash**: A SHA-256 hash of the input file's bytes is computed to ensure data integrity.
5. **Encrypt Data**: The file's bytes are encrypted using the initialized cipher.
6. **Save Encrypted File**: The salt, IV, hash, and encrypted data are written to the output file.

### Decryption Process

The decryption process involves the following steps:

1. **Extract Components**: The salt, IV, stored hash, and encrypted data are extracted from the input file.
2. **Generate Key**: A key is derived from the user-provided password and the extracted salt.
3. **Initialize Cipher**: The AES-CBC cipher is initialized in decryption mode with the derived key and extracted IV.
4. **Decrypt Data**: The encrypted data is decrypted using the initialized cipher.
5. **Verify Hash**: A SHA-256 hash of the decrypted data is computed and compared to the stored hash to ensure data integrity.
6. **Save Decrypted File**: The decrypted data is written to the output file if the hash verification is successful.

### Key Generation

Keys are generated using the PBKDF2 (Password-Based Key Derivation Function 2) with HMAC SHA-256. This process involves the following:

- **Password**: User-provided password.
- **Salt**: Randomly generated 16-byte salt.
- **Iterations**: 65,536 iterations to enhance security.
- **Key Length**: 256-bit key for AES encryption.

### SHA-256 Hashing

SHA-256 hashing is used to ensure the integrity of the encrypted and decrypted data. The `MessageDigest` class from Java's security package is used to compute the SHA-256 hash of the file's bytes.

## Technology Used

- **Spring Boot**: For building the standalone application with minimal configuration.
- **Java Cryptography Architecture (JCA)**: For implementing encryption, decryption, and hashing functionalities.
- **Apache Maven**: For project build management.

## Challenges

1. **Cipher Initialization**: Ensuring the correct initialization of the AES-CBC cipher with the appropriate parameters (key, IV) was a key challenge.
2. **Data Integrity Verification**: Implementing a robust method to verify data integrity using SHA-256 hashing and handling mismatches effectively required careful consideration.
3. **Exception Handling**: Properly managing exceptions during encryption and decryption processes, especially handling wrong passwords and corrupted files, was crucial for a seamless user experience.

## Conclusions

The `EncryptorService` provides a secure and reliable way to encrypt and decrypt files using password-based encryption with AES-CBC. The implementation ensures data integrity through SHA-256 hashing and robust exception handling. Future improvements could include adding support for different encryption algorithms and enhancing performance for large file encryption and decryption.

---

For any issues or contributions, please refer to the repository's issue tracker and contribution guidelines.
