/**
 * Client-Side Decryption Utilities
 * Decrypts Level 2 and Level 3 emails using private key from IndexedDB
 */

import { getMostRecentPrivateKey, getGroupKey, storeGroupKey } from './indexedDB';

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
 * Derive AES-256 key from shared secret using HKDF
 * CRITICAL: Uses 32 zero bytes as salt to match Python's HKDF(salt=None)
 */
const deriveAESKey = async (sharedSecret: Uint8Array): Promise<CryptoKey> => {
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  return await window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),  // 32 zero bytes - matches Python's salt=None
      info: new TextEncoder().encode('qmail-aes')
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
};

/**
 * Decrypt Level 2 Email (Kyber512 + AES-GCM)
 * 
 * Email body format:
 * kem_ct_b64: [base64]
 * ciphertext_b64: [base64]
 * nonce_b64: [base64]
 */
export const decryptLevel2Email = async (emailBody: string): Promise<string> => {
  try {
    // Extract encryption markers from email body
    const kemCtMatch = emailBody.match(/kem_ct_b64:\s*([A-Za-z0-9+/=]+)/);
    const ciphertextMatch = emailBody.match(/ciphertext_b64:\s*([A-Za-z0-9+/=]+)/);
    const nonceMatch = emailBody.match(/nonce_b64:\s*([A-Za-z0-9+/=]+)/);

    if (!kemCtMatch || !ciphertextMatch || !nonceMatch) {
      throw new Error('Invalid Level 2 encrypted email format');
    }

    const kemCtB64 = kemCtMatch[1];
    const ciphertextB64 = ciphertextMatch[1];
    const nonceB64 = nonceMatch[1];

    // Get private key from IndexedDB
    const keyData = await getMostRecentPrivateKey();
    if (!keyData) {
      throw new Error('No private key found. Please set up your device.');
    }

    const privateKeyB64 = keyData.private_key_b64;

    // Call backend to perform KEM decapsulation
    const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
    const token = getTokenFromCookie();

    const response = await fetch(`${apiUrl}/api/decrypt/level2`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      credentials: 'include',
      body: JSON.stringify({
        kem_ct_b64: kemCtB64,
        private_key_b64: privateKeyB64
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to decapsulate KEM');
    }

    const { shared_secret_b64 } = await response.json();
    const sharedSecret = base64ToUint8Array(shared_secret_b64);

    // Derive AES key from shared secret
    const aesKey = await deriveAESKey(sharedSecret);

    // Decrypt ciphertext with AES-GCM
    const ciphertext = base64ToUint8Array(ciphertextB64);
    const nonce = base64ToUint8Array(nonceB64);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      aesKey,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);

  } catch (error) {
    console.error('Level 2 decryption failed:', error);
    throw new Error('Failed to decrypt email');
  }
};

/**
 * Decrypt Level 3 Email (OTP + QKD)
 * 
 * Email body format:
 * otp_key_id: [uuid]
 * xor_ciphertext_b64: [base64]
 */
export const decryptLevel3Email = async (emailBody: string): Promise<string> => {
  try {
    // Extract encryption markers
    const keyIdMatch = emailBody.match(/otp_key_id:\s*([a-f0-9-]+)/);
    const ciphertextMatch = emailBody.match(/xor_ciphertext_b64:\s*([A-Za-z0-9+/=]+)/);

    if (!keyIdMatch || !ciphertextMatch) {
      throw new Error('Invalid Level 3 encrypted email format');
    }

    const otpKeyId = keyIdMatch[1];
    const xorCiphertextB64 = ciphertextMatch[1];

    // Get private key from IndexedDB
    const keyData = await getMostRecentPrivateKey();
    if (!keyData) {
      throw new Error('No private key found. Please set up your device.');
    }

    const deviceId = keyData.device_id;
    const privateKeyB64 = keyData.private_key_b64;

    // Call backend to unwrap OTP
    const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
    const token = getTokenFromCookie();

    const response = await fetch(`${apiUrl}/api/decrypt/level3`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      credentials: 'include',
      body: JSON.stringify({
        otp_key_id: otpKeyId,
        device_id: deviceId,
        private_key_b64: privateKeyB64
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to unwrap OTP');
    }

    const { otp_b64 } = await response.json();
    const otp = base64ToUint8Array(otp_b64);
    const xorCiphertext = base64ToUint8Array(xorCiphertextB64);

    // XOR decrypt
    const plaintext = new Uint8Array(xorCiphertext.length);
    for (let i = 0; i < xorCiphertext.length; i++) {
      plaintext[i] = xorCiphertext[i] ^ otp[i];
    }

    return new TextDecoder().decode(plaintext);

  } catch (error) {
    console.error('Level 3 decryption failed:', error);
    throw new Error('Failed to decrypt email');
  }
};

/**
 * Decrypt Group Encryption Key
 * Uses Kyber512 KEM to unwrap the group's shared AES key
 */
export const decryptGroupKey = async (groupId: number): Promise<string> => {
  try {
    // Check if we have cached group key
    const cachedKey = await getGroupKey(groupId);
    if (cachedKey) {
      console.log(`✅ Using cached group key for group ${groupId}`);
      return cachedKey.decrypted_aes_key_b64;
    }

    console.log(`🔑 Fetching encrypted group key for group ${groupId}`);

    // Get encrypted group key from server
    const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
    const token = getTokenFromCookie();

    const response = await fetch(`${apiUrl}/api/groups/${groupId}/key`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
      credentials: 'include',
    });

    if (!response.ok) {
      throw new Error('Failed to fetch group key');
    }

    const { encrypted_group_key } = await response.json();
    const encryptedKeyData = JSON.parse(encrypted_group_key);

    const { kem_ct_b64, wrapped_key_b64, nonce_b64 } = encryptedKeyData;

    // Get private key from IndexedDB
    const keyData = await getMostRecentPrivateKey();
    if (!keyData) {
      throw new Error('No private key found. Please set up your device.');
    }

    const privateKeyB64 = keyData.private_key_b64;

    // Call backend to perform KEM decapsulation
    const decapResponse = await fetch(`${apiUrl}/api/decrypt/level2`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      credentials: 'include',
      body: JSON.stringify({
        kem_ct_b64: kem_ct_b64,
        private_key_b64: privateKeyB64
      }),
    });

    if (!decapResponse.ok) {
      throw new Error('Failed to decapsulate group key');
    }

    const { shared_secret_b64 } = await decapResponse.json();
    const sharedSecret = base64ToUint8Array(shared_secret_b64);

    // Derive wrapping key from shared secret
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    const wrapKey = await window.crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: new TextEncoder().encode('qmail-group-key')
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Unwrap group AES key
    const wrappedKey = base64ToUint8Array(wrapped_key_b64);
    const nonce = base64ToUint8Array(nonce_b64);

    const groupAesKeyRaw = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode('group-key-wrap') },
      wrapKey,
      wrappedKey
    );

    const groupAesKeyB64 = btoa(String.fromCharCode(...new Uint8Array(groupAesKeyRaw)));

    // Cache the decrypted group key
    await storeGroupKey({
      group_id: groupId,
      decrypted_aes_key_b64: groupAesKeyB64,
      cached_at: new Date().toISOString()
    });

    console.log(`✅ Group key decrypted and cached for group ${groupId}`);

    return groupAesKeyB64;

  } catch (error) {
    console.error('Group key decryption failed:', error);
    throw new Error('Failed to decrypt group key');
  }
};

/**
 * Decrypt Group Message
 * Uses cached or fetched group AES key to decrypt message
 * 
 * Email body format:
 * Group ID: [number]
 * ciphertext_b64: [base64]
 * nonce_b64: [base64]
 */
export const decryptGroupMessage = async (emailBody: string): Promise<string> => {
  try {
    // Extract group ID and encryption data from email body
    const groupIdMatch = emailBody.match(/Group ID:\s*(\d+)/);
    const ciphertextMatch = emailBody.match(/ciphertext_b64:\s*([A-Za-z0-9+/=]+)/);
    const nonceMatch = emailBody.match(/nonce_b64:\s*([A-Za-z0-9+/=]+)/);

    if (!groupIdMatch || !ciphertextMatch || !nonceMatch) {
      throw new Error('Invalid group encrypted email format');
    }

    const groupId = parseInt(groupIdMatch[1]);
    const ciphertextB64 = ciphertextMatch[1];
    const nonceB64 = nonceMatch[1];

    // Get decrypted group AES key
    const groupAesKeyB64 = await decryptGroupKey(groupId);
    const groupAesKey = base64ToUint8Array(groupAesKeyB64);

    // Import AES key
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      groupAesKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    // Decrypt message
    const ciphertext = base64ToUint8Array(ciphertextB64);
    const nonce = base64ToUint8Array(nonceB64);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      aesKey,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);

  } catch (error) {
    console.error('Group message decryption failed:', error);
    throw new Error('Failed to decrypt group message');
  }
};

/**
 * Detect encryption level from email body
 */
export const detectEncryptionLevel = (emailBody: string): 1 | 2 | 3 | 'group' | null => {
  // Check for group encryption first
  if (emailBody.includes('Group ID:') && (emailBody.includes('GROUP MESSAGE') || emailBody.includes('Group:') || emailBody.includes('Group Level 2'))) {
    return 'group';
  }
  if (emailBody.includes('kem_ct_b64:') && emailBody.includes('ciphertext_b64:')) {
    return 2;
  }
  if (emailBody.includes('otp_key_id:') && emailBody.includes('xor_ciphertext_b64:')) {
    return 3;
  }
  if (emailBody.includes('ðŸ” ENCRYPTED WITH QMAIL')) {
    // Has encryption banner but no recognizable format
    return null;
  }
  return 1; // Standard email
};

/**
 * Main decryption function - detects level and decrypts accordingly
 */
export const decryptEmail = async (emailBody: string): Promise<string> => {
  const level = detectEncryptionLevel(emailBody);

  switch (level) {
    case 1:
      return emailBody; // No decryption needed
    case 2:
      return await decryptLevel2Email(emailBody);
    case 3:
      return await decryptLevel3Email(emailBody);
    case 'group':
      return await decryptGroupMessage(emailBody);
    default:
      throw new Error('Unknown encryption format');
  }
};

// Helper to get cookie token
const getTokenFromCookie = (): string | null => {
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === 'session_token') {
      return value;
    }
  }
  return null;
};