# Hybrid Post-Quantum Transport (Hybrid KEM TLS)

This module implements the **Hybrid Key Encapsulation Mechanism (KEM)** used to secure all Inter-Process Communication (IPC) within the IOI Kernel.

It addresses the **"Harvest Now, Decrypt Later"** threat model, where an adversary records encrypted traffic today to decrypt it years later once a Quantum Computer is available.

## The Hybrid Architecture

A "Hybrid" scheme combines a classical algorithm (Elliptic Curve Diffie-Hellman) with a Post-Quantum algorithm (Kyber/ML-KEM).

*   **Classical Layer:** ECDH (X25519 or NIST P-256). Provides robust, time-tested security against conventional computers.
*   **Post-Quantum Layer:** Kyber-768 or Kyber-1024 (ML-KEM). Provides mathematical hardness against Shor's Algorithm running on a Quantum Computer.

**Security Guarantee:** The session is secure as long as *at least one* of the two underlying algorithms remains unbroken. If Kyber has a flaw, ECDH protects the data. If ECDH falls to a Quantum Computer, Kyber protects the data.

## The Handshake Protocol

We implement a **Post-Handshake Key Exchange** pattern to integrate seamlessly with TLS 1.3:

1.  **Classical Handshake:** Standard TLS 1.3 handshake completes using ECDH. A temporary session key ($K_{tls}$) is established.
2.  **KEM Encapsulation:**
    *   The Server sends its Kyber Public Key ($PK_{pq}$) to the Client over the encrypted channel.
    *   The Client generates a random shared secret ($SS_{pq}$), encapsulates it against $PK_{pq}$ to create a ciphertext ($CT$), and sends $CT$ back to the Server.
3.  **Key Binding (KDF):**
    *   Both parties compute a new, final application key ($K_{app}$) using HKDF.
    *   Input: The TLS Exporter Secret (unique to the classical session).
    *   Salt: The KEM Shared Secret ($SS_{pq}$).
4.  **Rekeying:** The underlying transport switches to $K_{app}$ for all subsequent traffic (AEAD).

This ensures that even if the TLS handshake is retroactively broken by a Quantum Computer, the attacker cannot derive $K_{app}$ without breaking the Lattice cryptography of the KEM.