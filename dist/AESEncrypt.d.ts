/**
 * Error thrown when the padding in the decrypted data is invalid.
 */
export declare class InvalidPaddingError extends Error {
    constructor(message: string);
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
export declare function encryptAES(plaintext: string, password: string): string;
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
export declare function decryptAES(encryptedBase64: string, password: string): string;
