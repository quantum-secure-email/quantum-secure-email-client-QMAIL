/**
 * Kyber512 Cryptography Utility for QMail
 * Uses pqc-kyber library for post-quantum key generation
 * 
 * Install: npm install pqc-kyber
 */

// @ts-ignore - pqc-kyber may not have TypeScript definitions
import * as kyber from 'pqc-kyber';

export interface KyberKeypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Generate a Kyber512 keypair
 * This happens entirely client-side - private key never leaves browser
 */
export const generateKyberKeypair = async (): Promise<KyberKeypair> => {
  try {
    // Generate Kyber512 keypair
    const keypair = await kyber.KeyGen512();
    
    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.privateKey
    };
  } catch (error) {
    console.error('Failed to generate Kyber keypair:', error);
    throw new Error('Keypair generation failed');
  }
};

/**
 * Convert Uint8Array to Base64 string
 */
export const uint8ArrayToBase64 = (array: Uint8Array): string => {
  let binary = '';
  const len = array.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(array[i]);
  }
  return btoa(binary);
};

/**
 * Convert Base64 string to Uint8Array
 */
export const base64ToUint8Array = (base64: string): Uint8Array => {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

/**
 * Encapsulate: Generate shared secret using recipient's public key
 * Returns ciphertext and shared secret
 */
export const encapsulate = async (publicKeyB64: string): Promise<{
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}> => {
  try {
    const publicKey = base64ToUint8Array(publicKeyB64);
    const result = await kyber.Encaps512(publicKey);
    
    return {
      ciphertext: result.cipherText,
      sharedSecret: result.sharedSecret
    };
  } catch (error) {
    console.error('Encapsulation failed:', error);
    throw new Error('Encapsulation failed');
  }
};

/**
 * Decapsulate: Recover shared secret using private key
 */
export const decapsulate = async (
  ciphertextB64: string,
  privateKeyB64: string
): Promise<Uint8Array> => {
  try {
    const ciphertext = base64ToUint8Array(ciphertextB64);
    const privateKey = base64ToUint8Array(privateKeyB64);
    
    const sharedSecret = await kyber.Decaps512(ciphertext, privateKey);
    return sharedSecret;
  } catch (error) {
    console.error('Decapsulation failed:', error);
    throw new Error('Decapsulation failed');
  }
};

/**
 * AES-GCM Encryption using derived key from Kyber shared secret
 * Uses Web Crypto API
 */
export const encryptWithSharedSecret = async (
  plaintext: string,
  sharedSecret: Uint8Array
): Promise<{
  ciphertext: string;
  nonce: string;
}> => {
  try {
    // Derive AES-256 key from shared secret using HKDF
    const key = await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    const aesKey = await window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(),
        info: new TextEncoder().encode('qmail-aes')
      },
      key,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    // Generate random nonce
    const nonce = window.crypto.getRandomValues(new Uint8Array(12));

    // Encrypt plaintext
    const encodedPlaintext = new TextEncoder().encode(plaintext);
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      aesKey,
      encodedPlaintext
    );

    return {
      ciphertext: uint8ArrayToBase64(new Uint8Array(ciphertext)),
      nonce: uint8ArrayToBase64(nonce)
    };
  } catch (error) {
    console.error('Encryption failed:', error);
    throw new Error('Encryption failed');
  }
};

/**
 * AES-GCM Decryption using derived key from Kyber shared secret
 */
export const decryptWithSharedSecret = async (
  ciphertextB64: string,
  nonceB64: string,
  sharedSecret: Uint8Array
): Promise<string> => {
  try {
    // Derive AES-256 key from shared secret
    const key = await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    const aesKey = await window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(),
        info: new TextEncoder().encode('qmail-aes')
      },
      key,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const ciphertext = base64ToUint8Array(ciphertextB64);
    const nonce = base64ToUint8Array(nonceB64);

    // Decrypt
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      aesKey,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Decryption failed');
  }
};
