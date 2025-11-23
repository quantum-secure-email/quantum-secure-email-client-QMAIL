/**
 * IndexedDB Utility for QMail
 * Stores private keys AND group keys securely in the browser's IndexedDB
 * Private keys NEVER leave the client
 */

const DB_NAME = 'qmail_keystore';
const PRIVATE_KEYS_STORE = 'private_keys';
const GROUP_KEYS_STORE = 'group_keys';
const DB_VERSION = 2; // Incremented for new store

interface PrivateKeyData {
  device_id: string;
  private_key_b64: string;
  public_key_b64: string;
  created_at: string;
  algo: string;
}

interface GroupKeyData {
  group_id: number;
  group_aes_key_b64: string;  // Decrypted group AES key
  group_name: string;
  updated_at: string;
}

/**
 * Initialize IndexedDB with both stores
 */
const initDB = (): Promise<IDBDatabase> => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      
      // Create private keys store if it doesn't exist
      if (!db.objectStoreNames.contains(PRIVATE_KEYS_STORE)) {
        db.createObjectStore(PRIVATE_KEYS_STORE, { keyPath: 'device_id' });
      }
      
      // Create group keys store if it doesn't exist
      if (!db.objectStoreNames.contains(GROUP_KEYS_STORE)) {
        db.createObjectStore(GROUP_KEYS_STORE, { keyPath: 'group_id' });
      }
    };
  });
};

// ==================== PRIVATE KEY OPERATIONS ====================

/**
 * Store private key in IndexedDB
 */
export const storePrivateKey = async (data: PrivateKeyData): Promise<void> => {
  const db = await initDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([PRIVATE_KEYS_STORE], 'readwrite');
    const store = transaction.objectStore(PRIVATE_KEYS_STORE);
    const request = store.put(data);

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    
    transaction.oncomplete = () => db.close();
  });
};

/**
 * Get private key from IndexedDB by device_id
 */
export const getPrivateKey = async (device_id: string): Promise<PrivateKeyData | null> => {
  const db = await initDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([PRIVATE_KEYS_STORE], 'readonly');
    const store = transaction.objectStore(PRIVATE_KEYS_STORE);
    const request = store.get(device_id);

    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
    
    transaction.oncomplete = () => db.close();
  });
};

/**
 * Get all stored private keys
 */
export const getAllPrivateKeys = async (): Promise<PrivateKeyData[]> => {
  const db = await initDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([PRIVATE_KEYS_STORE], 'readonly');
    const store = transaction.objectStore(PRIVATE_KEYS_STORE);
    const request = store.getAll();

    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
    
    transaction.oncomplete = () => db.close();
  });
};

/**
 * Delete private key from IndexedDB
 */
export const deletePrivateKey = async (device_id: string): Promise<void> => {
  const db = await initDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([PRIVATE_KEYS_STORE], 'readwrite');
    const store = transaction.objectStore(PRIVATE_KEYS_STORE);
    const request = store.delete(device_id);

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    
    transaction.oncomplete = () => db.close();
  });
};

/**
 * Check if any private keys exist
 */
export const hasPrivateKeys = async (): Promise<boolean> => {
  const keys = await getAllPrivateKeys();
  return keys.length > 0;
};

/**
 * Get the most recent private key
 */
export const getMostRecentPrivateKey = async (): Promise<PrivateKeyData | null> => {
  const keys = await getAllPrivateKeys();
  if (keys.length === 0) return null;
  
  // Sort by created_at descending
  keys.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  return keys[0];
};

// ==================== GROUP KEY OPERATIONS ====================

/**
 * Store decrypted group AES key in IndexedDB
 */
export const storeGroupKey = async (data: GroupKeyData): Promise<void> => {
  const db = await initDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([GROUP_KEYS_STORE], 'readwrite');
    const store = transaction.objectStore(GROUP_KEYS_STORE);
    const request = store.put(data);

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    
    transaction.oncomplete = () => db.close();
  });
};

/**
 * Get group key from IndexedDB by group_id
 */
export const getGroupKey = async (group_id: number): Promise<GroupKeyData | null> => {
  const db = await initDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([GROUP_KEYS_STORE], 'readonly');
    const store = transaction.objectStore(GROUP_KEYS_STORE);
    const request = store.get(group_id);

    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
    
    transaction.oncomplete = () => db.close();
  });
};

/**
 * Get all stored group keys
 */
export const getAllGroupKeys = async (): Promise<GroupKeyData[]> => {
  const db = await initDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([GROUP_KEYS_STORE], 'readonly');
    const store = transaction.objectStore(GROUP_KEYS_STORE);
    const request = store.getAll();

    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
    
    transaction.oncomplete = () => db.close();
  });
};

/**
 * Delete group key from IndexedDB
 */
export const deleteGroupKey = async (group_id: number): Promise<void> => {
  const db = await initDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([GROUP_KEYS_STORE], 'readwrite');
    const store = transaction.objectStore(GROUP_KEYS_STORE);
    const request = store.delete(group_id);

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    
    transaction.oncomplete = () => db.close();
  });
};

/**
 * Clear all group keys (useful when logging out)
 */
export const clearAllGroupKeys = async (): Promise<void> => {
  const db = await initDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([GROUP_KEYS_STORE], 'readwrite');
    const store = transaction.objectStore(GROUP_KEYS_STORE);
    const request = store.clear();

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    
    transaction.oncomplete = () => db.close();
  });
};
