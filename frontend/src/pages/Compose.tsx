import { useState } from 'react';
import DashboardLayout from '@/components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Shield, Send, Info, AlertCircle } from 'lucide-react';
import { toast } from 'sonner';

// Helper to get token from cookie
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

const Compose = () => {
  const [recipient, setRecipient] = useState('');
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [encryptionLevel, setEncryptionLevel] = useState('1');
  const [sending, setSending] = useState(false);
  const [recipientInfo, setRecipientInfo] = useState<any>(null);
  const [checkingRecipient, setCheckingRecipient] = useState(false);

  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

  const encryptionLevels = [
    {
      value: '1',
      label: 'Level 1: Normal Gmail',
      description: 'Standard email encryption (TLS only)',
      color: 'text-muted-foreground',
      requiresDevice: false,
    },
    {
      value: '2',
      label: 'Level 2: Post-Quantum (Kyber + AES-GCM)',
      description: 'Quantum-resistant encryption with Kyber algorithm',
      color: 'text-primary',
      requiresDevice: true,
    },
    {
      value: '3',
      label: 'Level 3: OTP + QKD',
      description: 'One-Time Pad with Quantum Key Distribution (Maximum Security)',
      color: 'text-accent',
      requiresDevice: true,
    },
  ];

  const selectedLevel = encryptionLevels.find((level) => level.value === encryptionLevel);

  // Check if recipient has a registered device
  const checkRecipient = async (email: string) => {
    if (!email || !email.includes('@')) return;

    setCheckingRecipient(true);
    const token = getTokenFromCookie();

    try {
      const response = await fetch(`${apiUrl}/api/compose/check-recipient/${encodeURIComponent(email)}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setRecipientInfo(data);
        
        if (!data.has_device && (encryptionLevel === '2' || encryptionLevel === '3')) {
          toast.warning('Recipient has no encryption device', {
            description: 'Level 2 and 3 encryption require the recipient to have registered a device.',
          });
        }
      }
    } catch (error) {
      console.error('Error checking recipient:', error);
    } finally {
      setCheckingRecipient(false);
    }
  };

  // Handle recipient blur to check for device
  const handleRecipientBlur = () => {
    if (recipient) {
      checkRecipient(recipient);
    }
  };

  const handleSend = async () => {
    if (!recipient || !subject || !message) {
      toast.error('Please fill in all fields');
      return;
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(recipient)) {
      toast.error('Please enter a valid email address');
      return;
    }

    // Check if encryption level requires device
    const level = parseInt(encryptionLevel);
    if ((level === 2 || level === 3) && (!recipientInfo || !recipientInfo.has_device)) {
      toast.error('Encryption level requires recipient device', {
        description: 'Please choose Level 1 or ask the recipient to register a device in QMail.',
      });
      return;
    }

    setSending(true);
    const token = getTokenFromCookie();

    try {
      const response = await fetch(`${apiUrl}/api/compose/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          to: recipient,
          subject: subject,
          message: message,
          encryption_level: level,
          recipient_device_id: recipientInfo?.device_id || null,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to send email');
      }

      const result = await response.json();

      toast.success(
        `Email sent successfully using ${selectedLevel?.label}!`,
        {
          description: `Your message to ${recipient} has been encrypted and delivered.`,
        }
      );

      // Reset form
      setRecipient('');
      setSubject('');
      setMessage('');
      setEncryptionLevel('1');
      setRecipientInfo(null);
      
    } catch (error: any) {
      console.error('Error sending email:', error);
      toast.error('Failed to send email', {
        description: error.message || 'Please try again.',
      });
    } finally {
      setSending(false);
    }
  };

  return (
    <DashboardLayout>
      <div className="mx-auto max-w-4xl space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Compose Email</h1>
          <p className="text-muted-foreground">
            Send quantum-secure emails with multi-level encryption
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Send className="h-5 w-5" />
              New Message
            </CardTitle>
            <CardDescription>
              Compose and send your quantum-encrypted email
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor="recipient">Recipient Email</Label>
              <Input
                id="recipient"
                type="email"
                placeholder="recipient@example.com"
                value={recipient}
                onChange={(e) => setRecipient(e.target.value)}
                onBlur={handleRecipientBlur}
              />
              {recipientInfo && (
                <p className="text-sm text-muted-foreground">
                  {recipientInfo.has_device ? (
                    <span className="text-green-600">✓ Recipient has encryption device ready</span>
                  ) : (
                    <span className="text-yellow-600">⚠ Recipient has no encryption device (Level 1 only)</span>
                  )}
                </p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="subject">Subject</Label>
              <Input
                id="subject"
                placeholder="Enter email subject"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="message">Message</Label>
              <Textarea
                id="message"
                placeholder="Type your message here..."
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                rows={8}
                className="resize-none"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="encryption">Encryption Level</Label>
              <Select value={encryptionLevel} onValueChange={setEncryptionLevel}>
                <SelectTrigger id="encryption">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {encryptionLevels.map((level) => (
                    <SelectItem 
                      key={level.value} 
                      value={level.value}
                      disabled={level.requiresDevice && (!recipientInfo || !recipientInfo.has_device)}
                    >
                      {level.label}
                      {level.requiresDevice && ' (requires device)'}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              {selectedLevel && (
                <div className="flex items-start gap-2 rounded-lg border border-border bg-muted/50 p-3">
                  <Info className="mt-0.5 h-4 w-4 text-primary" />
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-foreground">
                      {selectedLevel.label}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {selectedLevel.description}
                    </p>
                  </div>
                </div>
              )}

              {selectedLevel?.requiresDevice && (!recipientInfo || !recipientInfo.has_device) && (
                <div className="flex items-start gap-2 rounded-lg border border-yellow-500/50 bg-yellow-500/10 p-3">
                  <AlertCircle className="mt-0.5 h-4 w-4 text-yellow-600" />
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-yellow-900 dark:text-yellow-100">
                      Recipient Device Required
                    </p>
                    <p className="text-xs text-yellow-700 dark:text-yellow-300">
                      The recipient must register a device in QMail to receive encrypted emails at this level.
                    </p>
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between border-t border-border pt-4">
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Shield className="h-4 w-4 text-primary" />
                <span>Your message will be encrypted before sending</span>
              </div>

              <Button
                variant="quantum"
                size="lg"
                onClick={handleSend}
                disabled={sending || checkingRecipient}
              >
                <Send className="mr-2 h-4 w-4" />
                {sending ? 'Sending...' : 'Send Email'}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-gradient-to-br from-primary/5 to-accent/5">
          <CardHeader>
            <CardTitle className="text-sm">About Encryption Levels</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm text-muted-foreground">
            <p>
              <strong className="text-foreground">Level 1:</strong> Uses standard Gmail
              encryption (TLS). Suitable for non-sensitive communications. Works with any email address.
            </p>
            <p>
              <strong className="text-foreground">Level 2:</strong> Implements post-quantum
              cryptography using the Kyber512 algorithm, protecting against future quantum attacks.
              Requires recipient to have a registered device.
            </p>
            <p>
              <strong className="text-foreground">Level 3:</strong> Maximum security using
              One-Time Pad encryption with Quantum Key Distribution for theoretically unbreakable encryption.
              Requires recipient to have a registered device.
            </p>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default Compose;