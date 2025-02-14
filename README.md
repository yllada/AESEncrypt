# AESEncrypt

AESEncrypt is a TypeScript package that provides functions to encrypt and decrypt strings using the AES-128-CBC algorithm. The implementation uses manual padding (PKCS#5/PKCS#7) and derives both the encryption key and the initialization vector (IV) deterministically from the original key using PBKDF2 and SHA‑1. This allows compatibility with implementations in other languages (for example, a version in Go), although **it is not recommended for environments where randomized encryption is required**.

## Features

- **AES-128-CBC:** Encryption and decryption using the AES algorithm in CBC mode.
- **Manual Padding:** Implementation of PKCS#5/PKCS#7 padding to adjust the block size.
- **Deterministic Derivation:** Both the key and IV are derived from the original key, ensuring deterministic results (compatible with Go implementations).
- **TypeScript:** Written in TypeScript, with included type definitions to facilitate its use in modern projects.

## Installation

You can install the package using npm or yarn:

```bash
npm install AESEncrypt
```

Or, if you use yarn:

```bash
yarn add AESEncrypt
```

## Usage

Below is a basic example of how to use the package:

```typescript
import { encryptAES, decryptAES } from 'AESEncrypt';

const key = 'secret_key';
const plaintext = 'Sample text to encrypt';

// Encrypt
const encryptedText = encryptAES(plaintext, key);
console.log('Encrypted text:', encryptedText);

// Decrypt
const decryptedText = decryptAES(encryptedText, key);
console.log('Decrypted text:', decryptedText);
```

## API

```javascript
encryptAES(plaintext: string, key: string): string
```

- **Description:** Encrypts a plaintext string using AES-128-CBC with PKCS#5 padding.
- **Parameters:**
  - `plaintext`: The text to be encrypted. **Must not be empty.**
  - `key`: The encryption key. **Must not be empty.**
- **Returns:** A Base64-encoded string representing the encrypted text.
- **Exceptions:** Throws an error if `plaintext` or `key` are empty.

```javascript
decryptAES(encryptedBase64: string, key: string): string
```

- **Description:** Decrypts an encrypted (Base64-encoded) text using AES-128-CBC with PKCS#5 padding.
- **Parameters:**
  - `encryptedBase64`: The Base64-encoded encrypted text. **Must not be empty.**
  - `key`: The decryption key. **Must not be empty.**
- **Returns:** The decrypted plaintext.
- **Exceptions:** Throws an error if `encryptedBase64` or `key` are empty, or if decryption fails (e.g., due to invalid padding).

## Contributions

Contributions are welcome! If you would like to improve this package or fix any issues, please follow these steps:

1. Fork the repository.
2. Create a branch with your improvement or fix.
3. Submit a Pull Request explaining the changes you made.

## License

This project is distributed under the [MIT](LICENSE) license.

## Contact

If you have any questions or suggestions, please open an [issue](https://github.com/yllada/AESEncrypt/issues) in the repository or contact me directly.
