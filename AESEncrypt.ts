import { randomBytes, createCipheriv, createDecipheriv, pbkdf2Sync } from 'crypto';

// Security constants optimized for banking/financial data
const ITERATION_COUNT = 210000; // OWASP 2023 recommendation for PBKDF2-SHA256
const SALT_LENGTH = 32; // 256 bits for salt
const KEY_LENGTH = 32; // AES-256 requires 32 bytes
const IV_LENGTH = 12; // GCM standard IV length (96 bits)
const AUTH_TAG_LENGTH = 16; // 128 bits authentication tag

/**
 * Error thrown when the padding in the decrypted data is invalid.
 */
export class InvalidPaddingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidPaddingError';
  }
}

/**
 * Derives a cryptographically strong encryption key from the provided password using PBKDF2-SHA256.
 * Uses a random salt to ensure unique key derivation for each encryption operation.
 *
 * @param password - The input password/key as a Buffer.
 * @param salt - Random salt for key derivation (must be stored with encrypted data).
 * @returns The derived 256-bit encryption key.
 * @throws {Error} If the input password is empty or salt is invalid.
 */
function deriveKey(password: Buffer, salt: Buffer): Buffer {
  if (password.length === 0) {
    throw new Error('Password cannot be empty');
  }
  if (salt.length !== SALT_LENGTH) {
    throw new Error(`Salt must be ${SALT_LENGTH} bytes`);
  }
  // PBKDF2 with SHA-256 and high iteration count (OWASP 2023 recommendation)
  return pbkdf2Sync(password, salt, ITERATION_COUNT, KEY_LENGTH, 'sha256');
}



/**
 * Encrypts a plaintext string using AES-256-GCM with authenticated encryption (AEAD).
 * 
 * Security features:
 * - AES-256-GCM: Provides both confidentiality and authenticity
 * - Random IV per encryption: Prevents pattern analysis
 * - Random salt: Ensures unique key derivation
 * - PBKDF2-SHA256 with 210,000 iterations: Resists brute-force attacks
 * - Authentication tag: Detects tampering
 *
 * Output format: Base64(salt || iv || authTag || ciphertext)
 *
 * @param plaintext - The sensitive text to encrypt (e.g., bank account number).
 * @param password - Strong password/key (min 16 chars recommended).
 * @returns Base64-encoded encrypted data with salt, IV, and auth tag.
 * @throws {Error} If plaintext or password is empty.
 */
export function encryptAES(plaintext: string, password: string): string {
  if (!plaintext) {
    throw new Error('Plaintext cannot be empty');
  }
  if (!password) {
    throw new Error('Password cannot be empty');
  }
  if (password.length < 16) {
    throw new Error('Password must be at least 16 characters for banking-grade security');
  }

  // Generate cryptographically secure random values
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  
  // Derive encryption key from password
  const passwordBuffer = Buffer.from(password, 'utf8');
  const key = deriveKey(passwordBuffer, salt);
  
  // Encrypt with AES-256-GCM (Authenticated Encryption)
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const plaintextBuffer = Buffer.from(plaintext, 'utf8');
  
  const encrypted = Buffer.concat([
    cipher.update(plaintextBuffer),
    cipher.final()
  ]);
  
  // Get authentication tag (proves data integrity)
  const authTag = cipher.getAuthTag();
  
  // Combine: salt || iv || authTag || encrypted
  // This allows decryption without storing salt/IV separately
  const combined = Buffer.concat([salt, iv, authTag, encrypted]);
  
  return combined.toString('base64');
}

/**
 * Decrypts a Base64-encoded AES-256-GCM encrypted string with authentication verification.
 *
 * Security features:
 * - Verifies authentication tag before decryption (tamper detection)
 * - Extracts salt and IV from encrypted data
 * - Derives the same key using PBKDF2-SHA256
 * - Throws error if data has been modified
 *
 * @param encryptedBase64 - Base64 string containing salt, IV, auth tag, and ciphertext.
 * @param password - The same password used for encryption.
 * @returns The decrypted plaintext.
 * @throws {Error} If encrypted text/password is empty, data is corrupted, or authentication fails.
 */
export function decryptAES(encryptedBase64: string, password: string): string {
  if (!encryptedBase64) {
    throw new Error('Encrypted text cannot be empty');
  }
  if (!password) {
    throw new Error('Password cannot be empty');
  }

  const combined = Buffer.from(encryptedBase64, 'base64');
  
  // Minimum size check: salt + iv + authTag + at least 1 byte of data
  const minSize = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH + 1;
  if (combined.length < minSize) {
    throw new Error('Invalid encrypted data: too short');
  }
  
  // Extract components from combined buffer
  let offset = 0;
  const salt = combined.subarray(offset, offset + SALT_LENGTH);
  offset += SALT_LENGTH;
  
  const iv = combined.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;
  
  const authTag = combined.subarray(offset, offset + AUTH_TAG_LENGTH);
  offset += AUTH_TAG_LENGTH;
  
  const encrypted = combined.subarray(offset);
  
  // Derive the same key using extracted salt
  const passwordBuffer = Buffer.from(password, 'utf8');
  const key = deriveKey(passwordBuffer, salt);
  
  // Decrypt with authentication verification
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  
  try {
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final() // This will throw if authentication fails
    ]);
    
    return decrypted.toString('utf8');
  } catch (error) {
    // Authentication failure or corrupted data
    throw new Error('Decryption failed: Invalid password or data has been tampered with');
  }
}
