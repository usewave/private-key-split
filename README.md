# Private Key Sharing System

A secure implementation of Shamir's Secret Sharing scheme for splitting and managing private keys. This system allows splitting a private key into multiple shares, where a subset of shares is required to reconstruct the original key.

## Features

- Split private keys into multiple shares (3 shares by default)
- Reconstruct private keys using a threshold of shares (2 shares minimum)
- Generate new compatible shares from existing ones
- Cryptographic integrity protection for shares
- Version control for share compatibility
- Share types: Device, Server, and Recovery shares
- Secure random number generation
- Galois Field (GF256) arithmetic for mathematical operations

## Installation

```bash
Clone the repository
git clone https://github.com/yourusername/private-key-split.git
cd private-key-split
```

## Install dependencies

```bash
npm install
```

## Environment Variables

```bash
PRIVATE_KEY=your_solana_private_key_here
```

## API Reference

### KeyManager

#### `splitKey(privateKey, totalShares, threshold)`

Splits a private key into multiple shares.

- `privateKey`: String - The private key to split
- `totalShares`: Number - Total number of shares to create
- `threshold`: Number - Minimum shares needed to reconstruct
- Returns: Array of share objects

#### `combineShares(shares)`

Reconstructs the private key from shares.

- `shares`: Array - Array of share objects
- Returns: String - The reconstructed private key

#### `generateNewShareFromTwo(share1, share2)`

Generates a new compatible share from two existing shares.

- `share1`: Object - First share
- `share2`: Object - Second share
- Returns: Object - A new compatible share
