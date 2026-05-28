# Cryptographic Algorithms & GOST Standards

A comprehensive collection of cryptographic algorithm implementations, covering Russian GOST standards, classic protocols, and hash function vulnerability analysis. 
The repository demonstrates versatility by implementing complex cryptographic math in both C# (.NET) and Python (Jupyter Notebooks).

## Repository Structure

This repository is organized by programming language and technology stack:

*   **[Python-Notebooks](/Python-Notebooks):** Jupyter Notebook implementations focusing on GOST standards and hash collision analysis.
*   **[CSharp-Labs](/CSharp-Labs):** Console applications built with C# .NET, featuring network protocol simulations and zero-knowledge proofs.

*(Note: If you have standalone C# lab folders in the root, they belong to the C# section).*

## Tech Stack
*   **C# / .NET:** System.Security.Cryptography, TCP Sockets, JSON serialization.
*   **Python:** Jupyter Notebooks, hashlib, cryptographic math implementations.

## Key Concepts Covered
*   **Symmetric Encryption:** Magma (Магма), Kuznyechik (Кузнечик), SP-Networks (СПХ).
*   **Hash Functions:** Streebog (Стрибог - ГОСТ 34.11), MD5 collision resistance analysis.
*   **Asymmetric Crypto & Signatures:** RSA, GOST 34.10-2018 Digital Signatures.
*   **Cryptographic Protocols:** Kerberos (TCP Sockets), Blind Signatures (Chaum), Zero-Knowledge Proofs (Fiat-Shamir).
*   **Architecture:** Client-Server simulation, File-based IPC, Multi-threading.

## Challenges & Learnings
*   Translating complex mathematical specifications (GOST standards) into working code.
*   Implementing network protocols (Kerberos) and understanding the challenges of IPC (Inter-Process Communication).
*   Analyzing the weaknesses of legacy hash functions (MD5) through practical collision searching.
