const crypto = require('crypto');

function deriveKey(passphrase) {
  return crypto.createHash('sha256').update(passphrase, 'utf8').digest();
}

function encryptString(plain, passphrase) {
  const key = deriveKey(passphrase);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]).toString('base64');
}

function decryptString(payloadB64, passphrase) {
  const key = deriveKey(passphrase);
  const data = Buffer.from(payloadB64, 'base64');
  if (data.length < 12 + 16) throw new Error('Invalid payload');
  const iv = data.slice(0, 12);
  const authTag = data.slice(12, 28);
  const ciphertext = data.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

// Roundtrip test
const secret = 'my-api-key-1234';
const passphrase = 'correct horse battery staple';
console.log('Secret:', secret);
const enc = encryptString(secret, passphrase);
console.log('Encrypted (base64):', enc);
const dec = decryptString(enc, passphrase);
console.log('Decrypted:', dec);

if (dec === secret) {
  console.log('Roundtrip OK');
  process.exit(0);
} else {
  console.error('Roundtrip FAILED');
  process.exit(2);
}
