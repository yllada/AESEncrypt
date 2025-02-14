import { createHash, createCipheriv, createDecipheriv, pbkdf2Sync, Cipher, Decipher } from 'crypto';

const ITERATION_COUNT = 65536;
const SALT_LENGTH = 16;
const KEY_LENGTH = 16;
const BLOCK_SIZE = 16;

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
 * Derives the encryption key and initialization vector (IV) from the provided key.
 *
 * The salt is generated as the SHA-1 hash of the key (20 bytes), and the full salt is used
 * with PBKDF2 to derive a 16-byte key. The IV is taken as the first 16 bytes of the salt.
 *
 * @param key - The input key as a Buffer.
 * @returns An object containing the derived key (`keyEnc`) and IV.
 * @throws {Error} If the input key is empty.
 */
function deriveKeyAndIV(key: Buffer): { keyEnc: Buffer; iv: Buffer } {
  if (key.length === 0) {
    throw new Error('Key cannot be empty');
  }
  const salt: Buffer = createHash('sha1').update(key).digest(); // 20 bytes from SHA-1.
  const keyEnc: Buffer = pbkdf2Sync(key, salt, ITERATION_COUNT, KEY_LENGTH, 'sha1');
  const iv: Buffer = salt.subarray(0, SALT_LENGTH);
  return { keyEnc, iv };
}

/**
 * Applies PKCS#5/PKCS#7 padding to the provided data.
 *
 * @param data - The Buffer to be padded.
 * @returns A new Buffer with the required padding added.
 */
function applyPKCS5Padding(data: Buffer): Buffer {
  const padding: number = BLOCK_SIZE - (data.length % BLOCK_SIZE);
  const paddingBuffer: Buffer = Buffer.alloc(padding, padding);
  return Buffer.concat([data, paddingBuffer]);
}

/**
 * Removes the PKCS#5/PKCS#7 padding from the provided data.
 *
 * @param data - The Buffer from which to remove the padding.
 * @returns The Buffer with padding removed.
 * @throws {InvalidPaddingError} If the padding size or content is invalid.
 */
function removePKCS5Padding(data: Buffer): Buffer {
  if (data.length === 0) return data;
  const padding: number = data[data.length - 1];

  if (padding < 1 || padding > BLOCK_SIZE) {
    throw new InvalidPaddingError('Invalid padding size');
  }
  
  // Check that all padding bytes have the same value.
  for (let i = data.length - padding; i < data.length; i++) {
    if (data[i] !== padding) {
      throw new InvalidPaddingError('Invalid padding bytes');
    }
  }
  
  return data.subarray(0, data.length - padding);
}

/**
 * Encrypts a plaintext string using AES-128-CBC with manual PKCS#5 padding.
 *
 * @param plaintext - The text to be encrypted.
 * @param key - The encryption key as a string.
 * @returns The encrypted text encoded in Base64.
 * @throws {Error} If the plaintext or key is empty.
 */
export function encryptAES(plaintext: string, key: string): string {
  if (!plaintext) {
    throw new Error('Plaintext cannot be empty');
  }
  if (!key) {
    throw new Error('Key cannot be empty');
  }
  const keyBuffer: Buffer = Buffer.from(key, 'utf8');
  const { keyEnc, iv } = deriveKeyAndIV(keyBuffer);
  const cipher: Cipher = createCipheriv('aes-128-cbc', keyEnc, iv);
  cipher.setAutoPadding(false); 
  const plaintextBuffer: Buffer = Buffer.from(plaintext, 'utf8');
  const paddedPlaintext: Buffer = applyPKCS5Padding(plaintextBuffer);
  const encryptedBuffer: Buffer = Buffer.concat([cipher.update(paddedPlaintext), cipher.final()]);
  return encryptedBuffer.toString('base64');
}

/**
 * Decrypts a Base64-encoded AES-128-CBC encrypted string using manual PKCS#5 padding.
 *
 * @param encryptedBase64 - The encrypted text in Base64 format.
 * @param key - The decryption key as a string.
 * @returns The decrypted plaintext.
 * @throws {Error} If the encrypted text or key is empty.
 * @throws {InvalidPaddingError} If the padding in the decrypted data is invalid.
 */
export function decryptAES(encryptedBase64: string, key: string): string {
  if (!encryptedBase64) {
    throw new Error('Encrypted text cannot be empty');
  }
  if (!key) {
    throw new Error('Key cannot be empty');
  }
  const keyBuffer: Buffer = Buffer.from(key, 'utf8');
  const { keyEnc, iv } = deriveKeyAndIV(keyBuffer);
  const decipher: Decipher = createDecipheriv('aes-128-cbc', keyEnc, iv);
  decipher.setAutoPadding(false); 
  const encryptedBuffer: Buffer = Buffer.from(encryptedBase64, 'base64');
  const decryptedBuffer: Buffer = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
  return removePKCS5Padding(decryptedBuffer).toString('utf8');
}
