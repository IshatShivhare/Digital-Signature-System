# Digital Signature-Based Document Authentication System

## Mini-Project Report

---

**Course**: AI-331 Information Security and Cryptography  
**Academic Year**: 2025-26  

---

## Project Team

| Name | Roll Number |
|----------------|-------------|
| Ishat Shivhare | U23AI071 |
| Atharva Gupta | U23AI084 |
| Aditya Gaur | U23AI095 |

---

## GitHub Repository

**Project Repository**: [https://github.com/IshatShivhare/Digital-Signature-System](https://github.com/IshatShivhare/Digital-Signature-System)

---

## Abstract

This project implements a comprehensive **Digital Signature-Based Document Authentication System** using RSA-2048 cryptography and SHA-256 hashing algorithms. The system provides a secure mechanism for signing digital documents and verifying their authenticity and integrity. The implementation includes a user-friendly GUI application that allows users to sign documents, verify signatures, generate QR codes for public key sharing, and detect tampering. The system demonstrates practical applications of public-key cryptography, hash functions, and digital signature standards in real-world document authentication scenarios.

**Keywords**: Digital Signatures, RSA, SHA-256, Document Authentication, Public Key Infrastructure, Cryptography.

---

## 1. Introduction

In the digital age, ensuring the authenticity, integrity, and non-repudiation of electronic documents is paramount. This project addresses the need for a secure and user-friendly system to apply and verify digital signatures. The primary objective was to design and implement a system using industry-standard cryptographic algorithms (RSA-2048 and SHA-256) that allows non-technical users to securely sign any digital file and verify the signature of others. The system provides a complete workflow from key generation and document signing to signature verification and public key sharing via QR codes.

---

## 2. Core Technologies & Signing Process

The system is built upon a foundation of proven cryptographic principles to ensure robust security.

### 2.1 Core Algorithms
*   **RSA-2048**: An asymmetric encryption algorithm used for the signature process. Its security relies on the difficulty of factoring large numbers. A 2048-bit key length provides a strong security level, considered safe until at least 2030.
*   **SHA-256**: A cryptographic hash function that produces a unique 256-bit (32-byte) "fingerprint" of a document. It is computationally efficient and resistant to collisions, ensuring that any change to the document results in a completely different hash.
*   **PSS (Probabilistic Signature Scheme)**: A secure padding scheme used with RSA to enhance security. It introduces randomness, making signatures non-deterministic and resistant to certain cryptographic attacks, providing provable security.

### 2.2 Digital Signature Workflow

The system follows the standard digital signature process, which is highly efficient as it only signs the fixed-size hash of a document, not the entire file.

**Signing Process**:
```
Document → Hash Function (SHA-256) → Hash → Encrypt with Private Key (RSA) → Signature
```
**Verification Process**:
```
Original Document → Hash Function (SHA-256) → Hash₁
Signature → Decrypt with Public Key (RSA) → Hash₂
Compare: Is Hash₁ == Hash₂? (If yes, signature is valid)
```
---

## 3. System Architecture and Implementation

The project is structured into a modular, multi-layered architecture to separate concerns and improve maintainability.

### 3.1 High-Level Architecture
```
┌─────────────────────────────────────────────────────┐
│ Presentation Layer (gui.py) │
│ (User Interface via Tkinter) │
└────────────────────┬────────────────────────────────┘
│
┌─────────────────────────────────────────────────────┐
│ Application Layer (signer.py, verifier.py) │
│ (Orchestrates Signing & Verification) │
└────────────────────┬────────────────────────────────┘
│
┌─────────────────────────────────────────────────────┐
│ Service Layer (metadata.py, qr_module.py) │
│ (Metadata Management, QR Generation) │
└────────────────────┬────────────────────────────────┘
│
┌─────────────────────────────────────────────────────┐
│ Cryptography Layer (crypto_core.py) │
│ (Core RSA, SHA-256, PSS Operations) │
└─────────────────────────────────────────────────────┘
```
### 3.2 Key Module Implementations

The core logic is distributed across several key Python files in the `src/` directory.

#### `crypto_core.py` (Cryptography Layer)
This module encapsulates all fundamental cryptographic operations, abstracting the `cryptography` library.

*   **`generate_rsa_keypair()`**: Creates a new 2048-bit RSA public/private key pair using a secure random number generator.
*   **`hash_file(filepath)`**: Computes the SHA-256 hash of a file. It reads the file in chunks to handle large files efficiently without consuming excessive memory.
*   **`sign_hash(private_key, hash_digest)`**: Signs a given hash using the provided RSA private key and the secure PSS padding scheme.
*   **`verify_signature(public_key, hash_digest, signature)`**: Attempts to verify a signature against a document's hash using the corresponding public key. Returns `True` if valid, `False` otherwise.
*   **`get_public_key_fingerprint(public_key)`**: Calculates a SHA-256 hash of the public key to create a short, verifiable fingerprint for out-of-band identity checks.

#### `signer.py` (Application Layer)
This module manages the end-to-end document signing workflow.

*   **`DocumentSigner` class**: The main class that orchestrates the signing process.
*   **`sign_document(document_path)`**: The primary method that:
    1.  Ensures an RSA key pair exists (generating one if not).
    2.  Hashes the target document using `crypto_core.hash_file()`.
    3.  Signs the resulting hash with the private key using `crypto_core.sign_hash()`.
    4.  Creates a metadata file containing the timestamp, file hash, and public key fingerprint.
    5.  Saves the binary signature (`.sig`) and JSON metadata (`.json`) files.

#### `verifier.py` (Application Layer)
This module handles the logic for verifying a document's signature.

*   **`SignatureVerifier` class**: Manages the verification workflow.
*   **`verify_document(doc_path, sig_path, key_path)`**: The main verification method that:
    1.  Loads the public key, the signature, and the document.
    2.  Calculates the SHA-256 hash of the provided document.
    3.  Calls `crypto_core.verify_signature()` to perform the core cryptographic check.
    4.  Optionally validates this against metadata (e.g., matching file hash, key fingerprint).
    5.  Returns a `VerificationResult` object with a clear success/failure status and detailed information.

#### `gui.py` (Presentation Layer)
This file contains the `DigitalSignatureGUI` class, which creates an intuitive user interface using Tkinter.

*   **Mode Selection**: Allows the user to switch between "Sign Document" and "Verify Signature" modes.
*   **File Dialogs**: Provides file browsers for easy selection of documents, signatures, and keys.
*   **`perform_signing()`**: A handler that calls the `DocumentSigner` logic and displays the results in a text area.
*   **`perform_verification()`**: A handler that uses the `SignatureVerifier` and displays a clear "VERIFIED" or "FAILED" message with details.
*   **Auto-Detection**: Intelligently finds associated `.sig` and `.pem` files when a document is selected for verification, simplifying the user's workflow.

---

## 4. Testing and Results

The system was rigorously tested to ensure its reliability and security.

### 4.1 Testing Strategy
Comprehensive unit tests were developed using the `pytest` framework, covering over 30 test cases, including:
*   **Valid Cases**: Signing and verifying documents of various types (text, binary, large files).
*   **Tampering Detection**: Verifying a signature against a document that has been modified by even a single bit.
*   **Invalid Key Detection**: Attempting to verify a signature with the wrong public key.
*   **Corrupted Data**: Testing with corrupted signature or key files.
*   **Edge Cases**: Handling empty files and missing inputs gracefully.

### 4.2 Key Results
*   **Functional Correctness**: The system successfully signs and verifies documents across all test cases.
*   **Integrity Enforcement**: Tampering was detected with **100% accuracy**. Any modification to the document after signing resulted in a verification failure.
*   **Authentication**: Using the incorrect public key for verification always resulted in a failure, confirming that the signer's identity is correctly bound to the signature.
*   **User Interface**: The GUI proved to be intuitive, enabling users to perform complex cryptographic operations without needing to understand the underlying principles.

#### Example Verification Output

**Successful Verification:**
```
✓ VERIFIED
Signature is VALID. The document is authentic and unmodified.
Details:
Document: document.pdf
Status: VERIFIED
Timestamp: 2024-11-16 14:35:22 UTC
Public Key Fingerprint: a7b3c9d2e8f14a6b...
```
**Failed Verification (Tampered Document):**
```
✗ VERIFICATION FAILED
Signature verification FAILED. The document may have been
modified or the signature is invalid.
Details:
Document: document.pdf
Status: INVALID
⚠ WARNING: DO NOT TRUST THIS DOCUMENT!
```
---

## 5. Security Analysis

The security of the system is founded on the strength of its cryptographic components and implementation best practices.

*   **Cryptographic Strength**: RSA-2048 and SHA-256 are industry standards that provide robust protection against forgery and tampering.
*   **Secure Padding**: The use of PSS padding mitigates common vulnerabilities associated with older RSA padding schemes.
*   **Key Protection**: The system's security relies on the user's ability to keep their private key secret. The system itself does not transmit private keys.
*   **Threats Mitigated**: The system effectively prevents document forgery, tampering, and repudiation. The public key fingerprint helps mitigate man-in-the-middle attacks by allowing users to verify keys through a separate, trusted channel.

---

## 6. Conclusion and Future Enhancements

This project successfully demonstrates the design and implementation of a complete digital signature system. We created a secure, modular, and user-friendly application that effectively leverages modern cryptography to ensure document authenticity and integrity. Key learning outcomes include a deep practical understanding of public-key infrastructure, hash functions, signature schemes, and secure software development practices.

**Potential Future Enhancements**:
1.  **Password-Protected Keys**: Encrypt the private key on disk with a user-defined password for an extra layer of security.
2.  **ECDSA Support**: Implement Elliptic Curve Digital Signature Algorithm (ECDSA) as an alternative, which offers similar security with smaller key sizes.
3.  **Batch Operations**: Add functionality to sign and verify multiple documents at once.
4.  **Certificate Integration**: Support X.509 certificates to integrate with a broader Public Key Infrastructure (PKI).

---
