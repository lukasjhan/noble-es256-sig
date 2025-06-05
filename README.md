# ES256 JWT Signature Implementation

This project demonstrates how to create and verify ES256 (ECDSA with P-256 curve and SHA-256) signatures for JWTs using the `noble-curves` library. ES256 is a widely used algorithm for signing JWTs, especially in scenarios requiring elliptic curve cryptography.

## Features

- ES256 signature generation using P-256 curve
- JWT creation with custom headers and payloads
- Signature verification using public key
- Uses industry-standard libraries:
  - `@noble/curves`: For elliptic curve operations
  - `@sd-jwt/utils, js-base64`: For base64url encoding
  - `@sd-jwt/hash`: For hash operations (internally uses @noble/hashes)
  - `jose`: For JWT verification testing only

## Why did I make this?

I'd like to sign JWT with ES256 algorithm without using platform-specific libraries or plaform's features(nodejs crypto, etc).

## Installation

```bash
pnpm install
```

## Usage

Run the test script to see the JWT generation and verification in action:

```bash
pnpm test
```

## About ES256

ES256 is a digital signature algorithm that combines:

- ECDSA (Elliptic Curve Digital Signature Algorithm)
- P-256 curve (also known as secp256r1 or prime256v1)
- SHA-256 hashing

It provides a good balance between security and performance, making it suitable for JWT signing in modern web applications.
