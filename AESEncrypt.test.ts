import { encryptAES, decryptAES } from './AESEncrypt';

const VALID_KEY = 'secret_key';
const PLAINTEXT = 'Sample text to encrypt';

describe('AES Encryption and Decryption', () => {
  describe('encryptAES', () => {
    it('should encrypt a non-empty plaintext and return a Base64 string different from the original text', () => {
      const encryptedText = encryptAES(PLAINTEXT, VALID_KEY);
      expect(encryptedText).toBeDefined();
      expect(typeof encryptedText).toBe('string');
      expect(encryptedText).not.toEqual(PLAINTEXT);
    });

    it('should produce deterministic output for the same plaintext and key', () => {
      const encryptedText1 = encryptAES(PLAINTEXT, VALID_KEY);
      const encryptedText2 = encryptAES(PLAINTEXT, VALID_KEY);
      expect(encryptedText1).toEqual(encryptedText2);
    });

    it('should throw an error if plaintext is empty', () => {
      expect(() => encryptAES('', VALID_KEY)).toThrow('Plaintext cannot be empty');
    });

    it('should throw an error if the key is empty', () => {
      expect(() => encryptAES(PLAINTEXT, '')).toThrow('Key cannot be empty');
    });
  });

  describe('decryptAES', () => {
    it('should correctly decrypt a previously encrypted text', () => {
      const encryptedText = encryptAES(PLAINTEXT, VALID_KEY);
      const decryptedText = decryptAES(encryptedText, VALID_KEY);
      expect(decryptedText).toEqual(PLAINTEXT);
    });

    it('should throw an error if the encrypted text is empty', () => {
      expect(() => decryptAES('', VALID_KEY)).toThrow('Encrypted text cannot be empty');
    });

    it('should throw an error if the key is empty', () => {
      const encryptedText = encryptAES(PLAINTEXT, VALID_KEY);
      expect(() => decryptAES(encryptedText, '')).toThrow('Key cannot be empty');
    });

    it('should throw an error when attempting to decrypt with an incorrect key', () => {
      const encryptedText = encryptAES(PLAINTEXT, VALID_KEY);
      const wrongKey = 'clave_incorrecta';
      expect(() => decryptAES(encryptedText, wrongKey)).toThrow();
    });
  });
});
