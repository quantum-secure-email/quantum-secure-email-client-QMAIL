/**
 * DeviceSetup Component
 * Automatically runs after OAuth login to:
 * 1. Check if user has a device registered
 * 2. If not, generate Kyber512 keypair client-side
 * 3. Store private key in IndexedDB
 * 4. Send public key to backend
 */

import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Progress } from '@/components/ui/progress';
import { Shield, Check, AlertCircle } from 'lucide-react';
import { toast } from 'sonner';
import { generateKyberKeypair, uint8ArrayToBase64 } from '@/utils/kyberCrypto';
import { storePrivateKey, hasPrivateKeys } from '@/utils/indexedDB';

const DeviceSetup = () => {
  const { user } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [status, setStatus] = useState<'checking' | 'generating' | 'registering' | 'complete' | 'error'>('checking');
  const [progress, setProgress] = useState(0);
  const [errorMessage, setErrorMessage] = useState('');

  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

  const setupDevice = async () => {
    try {
      // Step 1: Check if device already exists locally
      setStatus('checking');
      setProgress(10);
      
      const hasKeys = await hasPrivateKeys();
      if (hasKeys) {
        console.log('Device already set up');
        setStatus('complete');
        setProgress(100);
        setTimeout(() => setIsOpen(false), 1000);
        return;
      }

      // Step 2: Generate Kyber512 keypair
      setStatus('generating');
      setProgress(30);
      toast.info('Generating encryption keys...');

      const keypair = await generateKyberKeypair();
      const publicKeyB64 = uint8ArrayToBase64(keypair.publicKey);
      const privateKeyB64 = uint8ArrayToBase64(keypair.privateKey);

      setProgress(60);

      // Step 3: Register device with backend (send only public key)
      setStatus('registering');
      toast.info('Registering device...');

      const token = getTokenFromCookie();
      const response = await fetch(`${apiUrl}/device/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        credentials: 'include',
        body: JSON.stringify({
          pubkey_b64: publicKeyB64,
          device_name: getBrowserName(),
          algo: 'Kyber512'
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to register device');
      }

      const data = await response.json();
      const deviceId = data.device_id;

      setProgress(80);

      // Step 4: Store private key locally in IndexedDB
      await storePrivateKey({
        device_id: deviceId,
        private_key_b64: privateKeyB64,
        public_key_b64: publicKeyB64,
        created_at: new Date().toISOString(),
        algo: 'Kyber512'
      });

      setProgress(100);
      setStatus('complete');

      toast.success('🔐 Device setup complete!', {
        description: 'You can now send and receive encrypted emails'
      });

      // Close dialog after 2 seconds
      setTimeout(() => setIsOpen(false), 2000);

    } catch (error) {
      console.error('Device setup failed:', error);
      setStatus('error');
      setErrorMessage(error instanceof Error ? error.message : 'Unknown error');
      toast.error('Device setup failed', {
        description: 'Please try again or contact support'
      });
    }
  };

  useEffect(() => {
    // Only run if user is logged in
    if (user) {
      setIsOpen(true);
      setupDevice();
    }
  }, [user]);

  const getStatusMessage = () => {
    switch (status) {
      case 'checking':
        return 'Checking device status...';
      case 'generating':
        return 'Generating quantum-resistant keys...';
      case 'registering':
        return 'Registering your device...';
      case 'complete':
        return 'Setup complete!';
      case 'error':
        return 'Setup failed';
      default:
        return 'Setting up...';
    }
  };

  const getStatusIcon = () => {
    switch (status) {
      case 'complete':
        return <Check className="h-6 w-6 text-green-600" />;
      case 'error':
        return <AlertCircle className="h-6 w-6 text-red-600" />;
      default:
        return <Shield className="h-6 w-6 text-primary animate-pulse" />;
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogContent className="sm:max-w-md" onInteractOutside={(e) => e.preventDefault()}>
        <DialogHeader>
          <div className="flex items-center gap-3">
            {getStatusIcon()}
            <div>
              <DialogTitle>Device Setup</DialogTitle>
              <DialogDescription>{getStatusMessage()}</DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <Progress value={progress} className="h-2" />

          {status === 'error' && (
            <div className="rounded-md bg-red-50 p-3 text-sm text-red-800">
              <p className="font-medium">Error: {errorMessage}</p>
              <button
                onClick={setupDevice}
                className="mt-2 text-red-600 underline hover:text-red-800"
              >
                Try Again
              </button>
            </div>
          )}

          {status === 'complete' && (
            <div className="rounded-md bg-green-50 p-3 text-sm text-green-800">
              <p className="font-medium">✓ Your device is ready for quantum-secure communication</p>
            </div>
          )}

          {status !== 'error' && status !== 'complete' && (
            <div className="space-y-2 text-sm text-muted-foreground">
              <p>• Generating post-quantum cryptographic keys</p>
              <p>• Securing your private key locally</p>
              <p>• Registering with QMail servers</p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

// Helper functions

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

const getBrowserName = (): string => {
  const userAgent = navigator.userAgent;
  if (userAgent.includes('Chrome')) return 'Chrome';
  if (userAgent.includes('Firefox')) return 'Firefox';
  if (userAgent.includes('Safari')) return 'Safari';
  if (userAgent.includes('Edge')) return 'Edge';
  return 'Browser';
};

export default DeviceSetup;
