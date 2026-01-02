# AESEncrypt - Banking-Grade Encryption

**AESEncrypt** is a TypeScript package that provides **banking-grade encryption** for sensitive data using **AES-256-GCM** (Galois/Counter Mode). This implementation meets modern cryptographic standards with authenticated encryption (AEAD), random IVs, and strong key derivation using PBKDF2-SHA256.

⚠️ **Designed for:** Financial data, bank accounts, personal identification numbers, and other sensitive information requiring high security standards.

✅ **Security Features:**
- AES-256-GCM with authenticated encryption
- Random IV per encryption (prevents pattern analysis)
- PBKDF2-SHA256 with 210,000 iterations (OWASP 2023)
- Tamper detection via authentication tags
- Minimum 16-character password requirement

## Features

- **🔒 AES-256-GCM:** Military-grade encryption with 256-bit keys and authenticated encryption (AEAD)
- **🎲 Random IV Generation:** Each encryption uses a unique, cryptographically secure random IV
- **🧂 Random Salt:** 32-byte random salt per operation ensures unique key derivation
- **🛡️ Tamper Detection:** Authentication tags detect any data modification or corruption
- **🔑 Strong Key Derivation:** PBKDF2-SHA256 with 210,000 iterations (OWASP 2023 recommendation)
- **✅ Banking Security Standards:** Meets OWASP, NIST, and modern cryptographic best practices
- **📘 TypeScript:** Full type definitions for seamless integration in modern projects
- **🧪 Thoroughly Tested:** Comprehensive test suite validates security features

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

### Basic Example

```typescript
import { encryptAES, decryptAES } from 'AESEncrypt';

// Use a strong password (minimum 16 characters)
const password = 'MySecureBankingPassword2026!';
const bankAccountNumber = '1234-5678-9012-3456';

// Encrypt sensitive data
const encryptedData = encryptAES(bankAccountNumber, password);
console.log('Encrypted:', encryptedData);
// Output: Long Base64 string containing salt, IV, auth tag, and ciphertext

// Decrypt when needed
const decryptedData = decryptAES(encryptedData, password);
console.log('Decrypted:', decryptedData);
// Output: "1234-5678-9012-3456"
```

### Important Security Notes

⚠️ **Each encryption produces a different output** (even with same input) due to random IV:

```typescript
const data = 'Account: 9876543210';
const encrypted1 = encryptAES(data, password);
const encrypted2 = encryptAES(data, password);

// These will be DIFFERENT (prevents pattern analysis)
console.log(encrypted1 !== encrypted2); // true

// But both decrypt to the same value
console.log(decryptAES(encrypted1, password) === data); // true
console.log(decryptAES(encrypted2, password) === data); // true
```

✅ **Tamper detection automatically**:

```typescript
try {
  const encrypted = encryptAES('Sensitive data', password);
  
  // If data is modified/corrupted, decryption fails
  const tamperedData = encrypted.slice(0, -10) + 'HACKED!';
  decryptAES(tamperedData, password); // Throws error
} catch (error) {
  console.error('Data has been tampered with!');
}
```

## API Reference

### `encryptAES(plaintext: string, password: string): string`

Encrypts a plaintext string using **AES-256-GCM** with authenticated encryption.

**Security Implementation:**
- Generates cryptographically secure random salt (32 bytes)
- Generates random IV (12 bytes) for each encryption
- Derives 256-bit key using PBKDF2-SHA256 (210,000 iterations)
- Encrypts with AES-256-GCM (provides confidentiality + authenticity)
- Returns: Base64(salt || iv || authTag || ciphertext)

**Parameters:**
- `plaintext` (string): The sensitive data to encrypt (e.g., bank account, SSN)
  - **Must not be empty**
- `password` (string): Strong password for encryption
  - **Minimum 16 characters required**
  - **Recommendation:** Use 20+ characters with mixed case, numbers, and symbols

**Returns:**
- Base64-encoded string containing: salt + IV + authentication tag + encrypted data
- Length: Typically 100+ characters (varies with plaintext length)

**Throws:**
- `Error`: If plaintext is empty
- `Error`: If password is empty
- `Error`: If password is less than 16 characters

**Example:**
```typescript
const encrypted = encryptAES('4532-1234-5678-9010', 'MyStrongPassword123!');
// Returns: "8h3Kd..." (long Base64 string)
```

---

### `decryptAES(encryptedBase64: string, password: string): string`

Decrypts AES-256-GCM encrypted data with **automatic authentication verification**.

**Security Implementation:**
- Extracts salt, IV, and authentication tag from encrypted data
- Derives the same 256-bit key using PBKDF2-SHA256
- Verifies authentication tag (detects tampering)
- Decrypts only if authentication passes

**Parameters:**
- `encryptedBase64` (string): Base64 string from `encryptAES()`
  - **Must not be empty**
  - **Must not be modified** (authentication will fail)
- `password` (string): The same password used for encryption
  - **Must not be empty**

**Returns:**
- Original decrypted plaintext string

**Throws:**
- `Error`: If encrypted text is empty
- `Error`: If password is empty
- `Error`: If data is too short or corrupted
- `Error`: If password is incorrect
- `Error`: If data has been tampered with (authentication fails)

**Example:**
```typescript
const decrypted = decryptAES(encryptedData, 'MyStrongPassword123!');
// Returns: "4532-1234-5678-9010"
```

---

### Error Handling

```typescript
try {
  const encrypted = encryptAES(accountNumber, password);
  // Store encrypted data safely
  
  const decrypted = decryptAES(encrypted, password);
  // Use decrypted data
} catch (error) {
  if (error.message.includes('tampered')) {
    console.error('Security alert: Data has been modified!');
  } else if (error.message.includes('password')) {
    console.error('Invalid password or corrupted data');
  } else {
    console.error('Encryption/decryption error:', error.message);
  }
}
```

## Security Best Practices

### ✅ Do's

1. **Use Strong Passwords**
   ```typescript
   // Good: 20+ characters, mixed case, numbers, symbols
   const password = 'Secure!Bank#Pass2026$Complex';
   ```

2. **Store Passwords Securely**
   - Use environment variables (never hardcode)
   - Use key management systems (AWS KMS, Azure Key Vault, GCP KMS)
   - Rotate passwords periodically

3. **Protect Encrypted Data**
   - Store in secure databases with access controls
   - Use HTTPS/TLS for transmission
   - Enable database encryption at rest

4. **Handle Errors Properly**
   ```typescript
   try {
     const decrypted = decryptAES(data, password);
   } catch (error) {
     // Log security events
     securityLogger.alert('Decryption failed', { error });
   }
   ```

5. **Implement Rate Limiting**
   - Prevent brute-force attacks on decryption
   - Add delays after failed attempts

### ❌ Don'ts

1. **Never use weak passwords**
   ```typescript
   // BAD - Will throw error
   encryptAES(data, 'short'); // < 16 chars
   ```

2. **Never hardcode passwords in source code**
   ```typescript
   // BAD
   const password = 'my_secret_key';
   
   // GOOD
   const password = process.env.ENCRYPTION_KEY;
   ```

3. **Never share encrypted data without secure channels**
   - Always use HTTPS
   - Consider additional transport encryption

4. **Never ignore decryption errors**
   - Authentication failures indicate tampering
   - Log and investigate all failures

### 🏢 Production Deployment Checklist

For banking/financial applications, also implement:

- [ ] **Key Management System** (AWS KMS, Azure Key Vault, etc.)
- [ ] **Audit Logging** (track all encryption/decryption operations)
- [ ] **Access Controls** (role-based access to encryption keys)
- [ ] **Key Rotation** (periodic password/key changes)
- [ ] **Backup Strategy** (encrypted backups with separate keys)
- [ ] **Monitoring & Alerts** (detect unusual decryption patterns)
- [ ] **Compliance Validation** (PCI-DSS, GDPR, SOC 2, etc.)
- [ ] **Security Audits** (regular penetration testing)
- [ ] **Disaster Recovery** (key recovery procedures)

### 📊 Compliance & Standards

This implementation follows:

- ✅ **OWASP 2023** - Cryptographic recommendations
- ✅ **NIST SP 800-132** - PBKDF2 guidelines
- ✅ **NIST SP 800-38D** - GCM mode recommendations
- ✅ **FIPS 197** - AES specification

**Note:** While this library provides strong cryptographic primitives, **full compliance** (PCI-DSS, HIPAA, etc.) requires additional infrastructure (HSMs, audit trails, access controls).

## Technical Details

### Encryption Process

1. Generate 32-byte random salt
2. Generate 12-byte random IV
3. Derive 256-bit key using PBKDF2-SHA256 (210,000 iterations)
4. Encrypt plaintext with AES-256-GCM
5. Get 16-byte authentication tag
6. Concatenate: `salt || iv || authTag || ciphertext`
7. Encode to Base64

### Decryption Process

1. Decode Base64 to buffer
2. Extract salt (bytes 0-31)
3. Extract IV (bytes 32-43)
4. Extract auth tag (bytes 44-59)
5. Extract ciphertext (bytes 60+)
6. Derive same 256-bit key using salt
7. Verify authentication tag
8. Decrypt if authentication passes

### Performance

- **Encryption:** ~250-500ms per operation (PBKDF2 is intentionally slow)
- **Decryption:** ~250-500ms per operation
- **Key Derivation:** ~99% of execution time (security by design)

**Note:** The slow key derivation is a **security feature** that makes brute-force attacks impractical.

## Contributions

Contributions are welcome! If you would like to improve this package or fix any issues, please follow these steps:

1. Fork the repository.
2. Create a branch with your improvement or fix.
3. Submit a Pull Request explaining the changes you made.

## License

This project is distributed under the [MIT](LICENSE) license.

## Contact

If you have any questions or suggestions, please open an [issue](https://github.com/yllada/AESEncrypt/issues) in the repository or contact me directly.
