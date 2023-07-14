const assert = require('assert');
const Crypto = require('crypto');

describe('Encryption and Decryption', function() {
  const secret_key = 'fd85b494-aaaa';
  const secret_iv = 'smslt';
  const encryptionMethod = 'AES-256-CBC';

  const key = Crypto.createHash('sha512')
    .update(secret_key, 'utf-8')
    .digest('hex')
    .substring(0, 32);
  const iv = Crypto.createHash('sha512')
    .update(secret_iv, 'utf-8')
    .digest('hex')
    .substring(0, 16);

  const plainText = 'hello';
  const encryptedMessage = 'L2dOZjlDVmxoSDNWdmpVMkNGd0JEdz09';

  it('should encrypt the plain text', function() {
    const encrypted = encrypt_string(plainText, encryptionMethod, key, iv);
    assert.strictEqual(encrypted, encryptedMessage);
  });

  it('should decrypt the encrypted message', function() {
    const decrypted = decrypt_string(encryptedMessage, encryptionMethod, key, iv);
    assert.strictEqual(decrypted, plainText);
  });

  // Helper functions

  function encrypt_string(plain_text, encryptionMethod, secret, iv) {
    const encryptor = Crypto.createCipheriv(encryptionMethod, secret, iv);
    const aes_encrypted =
      encryptor.update(plain_text, 'utf8', 'base64') + encryptor.final('base64');
    return Buffer.from(aes_encrypted).toString('base64');
  }

  function decrypt_string(encryptedMessage, encryptionMethod, secret, iv) {
    const buff = Buffer.from(encryptedMessage, 'base64');
    const decryptedString = buff.toString('utf-8');
    const decryptor = Crypto.createDecipheriv(encryptionMethod, secret, iv);
    return decryptor.update(decryptedString, 'base64', 'utf8') + decryptor.final('utf8');
  }
});
