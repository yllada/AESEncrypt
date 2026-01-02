import { encryptAES, decryptAES } from './AESEncrypt';

const VALID_KEY = 'ThisIsASecurePasswordForBanking123!'; // Banking-grade: 16+ chars
const PLAINTEXT = '1234567890123456'; // Simulates bank account number

describe('AES-256-GCM Banking Encryption', () => {
  describe('encryptAES', () => {
    it('should encrypt a non-empty plaintext and return a Base64 string different from the original text', () => {
      const encryptedText = encryptAES(PLAINTEXT, VALID_KEY);
      expect(encryptedText).toBeDefined();
      expect(typeof encryptedText).toBe('string');
      expect(encryptedText).not.toEqual(PLAINTEXT);
    });

    it('should produce DIFFERENT output for the same plaintext and key (random IV)', () => {
      const encryptedText1 = encryptAES(PLAINTEXT, VALID_KEY);
      const encryptedText2 = encryptAES(PLAINTEXT, VALID_KEY);
      // With random IV, same data should encrypt differently (critical for banking)
      expect(encryptedText1).not.toEqual(encryptedText2);
      
      // But both should decrypt to same plaintext
      expect(decryptAES(encryptedText1, VALID_KEY)).toEqual(PLAINTEXT);
      expect(decryptAES(encryptedText2, VALID_KEY)).toEqual(PLAINTEXT);
    });

    it('should throw an error if plaintext is empty', () => {
      expect(() => encryptAES('', VALID_KEY)).toThrow('Plaintext cannot be empty');
    });

    it('should throw an error if the password is empty', () => {
      expect(() => encryptAES(PLAINTEXT, '')).toThrow('Password cannot be empty');
    });

    it('should throw an error if password is too short (banking security)', () => {
      expect(() => encryptAES(PLAINTEXT, 'short')).toThrow('Password must be at least 16 characters');
    });

    it('should successfully encrypt sensitive banking data', () => {
      const bankAccount = '1234-5678-9012-3456';
      const encrypted = encryptAES(bankAccount, VALID_KEY);
      expect(encrypted).toBeTruthy();
      expect(encrypted.length).toBeGreaterThan(100); // GCM adds salt+IV+tag
    });
  });

  describe('decryptAES', () => {
    it('should correctly decrypt a previously encrypted text', () => {
      const encryptedText = encryptAES(PLAINTEXT, VALID_KEY);
      const decryptedText = decryptAES(encryptedText, VALID_KEY);
      expect(decryptedText).toEqual(PLAINTEXT);
    });

    it('should decrypt multiple different encryptions of same data', () => {
      const data = '9876543210';
      const encrypted1 = encryptAES(data, VALID_KEY);
      const encrypted2 = encryptAES(data, VALID_KEY);
      
      expect(decryptAES(encrypted1, VALID_KEY)).toEqual(data);
      expect(decryptAES(encrypted2, VALID_KEY)).toEqual(data);
    });

    it('should throw an error if the encrypted text is empty', () => {
      expect(() => decryptAES('', VALID_KEY)).toThrow('Encrypted text cannot be empty');
    });

    it('should throw an error if the password is empty', () => {
      const encryptedText = encryptAES(PLAINTEXT, VALID_KEY);
      expect(() => decryptAES(encryptedText, '')).toThrow('Password cannot be empty');
    });

    it('should throw an error when attempting to decrypt with an incorrect password', () => {
      const encryptedText = encryptAES(PLAINTEXT, VALID_KEY);
      const wrongKey = 'WrongPasswordForBankingData123!';
      expect(() => decryptAES(encryptedText, wrongKey)).toThrow('Decryption failed');
    });

    it('should detect tampered data (authentication tag verification)', () => {
      const encrypted = encryptAES(PLAINTEXT, VALID_KEY);
      const buffer = Buffer.from(encrypted, 'base64');
      
      // Tamper with a byte in the middle
      buffer[buffer.length - 10] ^= 0xFF;
      const tamperedEncrypted = buffer.toString('base64');
      
      expect(() => decryptAES(tamperedEncrypted, VALID_KEY))
        .toThrow('Decryption failed: Invalid password or data has been tampered with');
    });

    it('should reject data that is too short (corrupted)', () => {
      const tooShort = Buffer.from('short').toString('base64');
      expect(() => decryptAES(tooShort, VALID_KEY))
        .toThrow('Invalid encrypted data: too short');
    });
  });
});
