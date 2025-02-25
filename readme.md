# Ethereum Message Encryption Script

This Rust script implements ECIES (Elliptic Curve Integrated Encryption Scheme) encryption/decryption for Ethereum-compatible messages.

## Prerequisites

- Rust and Cargo (Latest stable version)
- Git

## Setup

1. Create a new Rust project:

```bash
cargo new eth_encryption
cd eth_encryption
```
2. Add the following dependencies to your `Cargo.toml`:

```toml
[dependencies]
aes-gcm = "0.10"
generic-array = "0.14"
hex = "0.4"
rand = "0.8"
secp256k1 = { version = "0.24", features = ["rand", "recovery", "std"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
hmac = "0.12"
sha2 = "0.10"
```

3. Copy the provided code into src/main.rs

Running the Script

```bash
   cargo build
   cargo run
```

Expected Output

The script will:

- Decrypt a sample encrypted message
- Generate and encrypt a new message
- Display various debug information including:
  (Shared secrets, Keys, Encrypted/decrypted messages, MAC values)

Troubleshooting

🐛 If you encounter any errors:

- Verify all dependencies are correctly specified in Cargo.toml
- Ensure you're using the latest stable Rust version
- Check that the input hex values are valid

File Structure

```
eth_encryption/
├── Cargo.toml
├── src/
│   └── main.rs
└── README.md
```