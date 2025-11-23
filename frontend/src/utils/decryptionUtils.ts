/**
 * Client-Side Decryption Utilities
 * Decrypts Level 2, Level 3, and Group emails using private key from IndexedDB
 */

import { getMostRecentPrivateKey, getGroupKey, storeGroupKey } from './indexedDB';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

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
 * Convert Uint8Array to Base64
 */
export const uint8ArrayToBase64 = (bytes: Uint8Array): string => {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
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

    // Call backend to decapsulate KEM (Kyber decapsulation happens server-side)
    const response = await fetch(`${API_BASE_URL}/debug/decrypt-level2`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({
        recipient_priv_b64: keyData.private_key_b64,
        kem_ct_b64: kemCtB64,
        nonce_b64: nonceB64,
        ciphertext_b64: ciphertextB64
      })
    });

    if (!response.ok) {
      throw new Error(`Decryption failed: ${response.statusText}`);
    }

    const data = await response.json();
    const plaintextB64 = data.plaintext_b64;
    
    // Decode plaintext
    const plaintextBytes = base64ToUint8Array(plaintextB64);
    return new TextDecoder().decode(plaintextBytes);

  } catch (error) {
    console.error('Level 2 decryption error:', error);
    throw error;
  }
};

/**
 * Decrypt Group Level 2 Email
 * 
 * Email body format:
 * group_id: [number]
 * group_name: [string]
 * nonce_b64: [base64]
 * ciphertext_b64: [base64]
 */
export const decryptGroupLevel2Email = async (emailBody: string): Promise<string> => {
  try {
    // Extract group encryption markers
    const groupIdMatch = emailBody.match(/group_id:\s*(\d+)/);
    const groupNameMatch = emailBody.match(/group_name:\s*([^\n]+)/);
    const nonceMatch = emailBody.match(/nonce_b64:\s*([A-Za-z0-9+/=]+)/);
    const ciphertextMatch = emailBody.match(/ciphertext_b64:\s*([A-Za-z0-9+/=]+)/);

    if (!groupIdMatch || !nonceMatch || !ciphertextMatch) {
      throw new Error('Invalid Group Level 2 encrypted email format');
    }

    const groupId = parseInt(groupIdMatch[1]);
    const groupName = groupNameMatch ? groupNameMatch[1].trim() : 'Unknown Group';
    const nonceB64 = nonceMatch[1];
    const ciphertextB64 = ciphertextMatch[1];

    // Check if we have the group key cached
    let groupKeyData = await getGroupKey(groupId);
    
    if (!groupKeyData) {
      // Fetch and decrypt group key from backend
      groupKeyData = await fetchAndDecryptGroupKey(groupId, groupName);
    }

    // Decrypt message with group AES key
    const groupAesKey = base64ToUint8Array(groupKeyData.group_aes_key_b64);
    const nonce = base64ToUint8Array(nonceB64);
    const ciphertext = base64ToUint8Array(ciphertextB64);

    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      groupAesKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const plaintextBytes = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: new TextEncoder().encode('qmail-group-level2')
      },
      aesKey,
      ciphertext
    );

    return new TextDecoder().decode(plaintextBytes);

  } catch (error) {
    console.error('Group Level 2 decryption error:', error);
    throw error;
  }
};

/**
 * Fetch encrypted group key from backend and decrypt it with user's private key
 */
async function fetchAndDecryptGroupKey(groupId: number, groupName: string): Promise<{
  group_id: number;
  group_aes_key_b64: string;
  group_name: string;
  updated_at: string;
}> {
  try {
    // Get user's private key
    const keyData = await getMostRecentPrivateKey();
    if (!keyData) {
      throw new Error('No private key found');
    }

    // Fetch encrypted group key from backend
    const response = await fetch(`${API_BASE_URL}/groups/${groupId}/key`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include'
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch group key: ${response.statusText}`);
    }

    const { encrypted_group_key } = await response.json();

    // Decrypt the encrypted package
    // Format: base64(JSON({kem_ct, nonce, ciphertext}))
    const packageJson = atob(encrypted_group_key);
    const package_ = JSON.parse(packageJson);

    // Call backend to decapsulate KEM
    const decapResponse = await fetch(`${API_BASE_URL}/debug/decrypt-level2`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({
        recipient_priv_b64: keyData.private_key_b64,
        kem_ct_b64: package_.kem_ct,
        nonce_b64: package_.nonce,
        ciphertext_b64: package_.ciphertext
      })
    });

    if (!decapResponse.ok) {
      throw new Error('Failed to decrypt group key');
    }

    const { plaintext_b64 } = await decapResponse.json();

    // Store decrypted group key in IndexedDB
    const groupKeyData = {
      group_id: groupId,
      group_aes_key_b64: plaintext_b64,
      group_name: groupName,
      updated_at: new Date().toISOString()
    };

    await storeGroupKey(groupKeyData);

    return groupKeyData;

  } catch (error) {
    console.error('Error fetching/decrypting group key:', error);
    throw error;
  }
}

/**
 * Detect encryption type from email body
 */
export const detectEncryptionType = (emailBody: string): 'level2' | 'group_level2' | 'plain' => {
  if (emailBody.includes('group_id:') && emailBody.includes('GROUP ENCRYPTED PAYLOAD')) {
    return 'group_level2';
  }
  
  if (emailBody.includes('kem_ct_b64:') && emailBody.includes('ENCRYPTED PAYLOAD')) {
    return 'level2';
  }
  
  return 'plain';
};

/**
 * Universal decrypt function - detects type and decrypts accordingly
 */
export const decryptEmail = async (emailBody: string): Promise<string> => {
  const type = detectEncryptionType(emailBody);
  
  if (type === 'level2') {
    return await decryptLevel2Email(emailBody);
  } else if (type === 'group_level2') {
    return await decryptGroupLevel2Email(emailBody);
  } else {
    return emailBody; // Plain text
  }
};
