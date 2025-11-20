/**
 * Updated ComposeEmail Component
 * Features:
 * - Real-time recipient checking (debounced)
 * - Dynamic Level 2/3 button enable/disable based on recipient device status
 * - Integration with Kyber encryption
 */

import { useState, useEffect, useCallback } from 'react';
import DashboardLayout from '@/components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Shield, Send, Info, AlertCircle, CheckCircle2 } from 'lucide-react';
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

// Debounce function
const useDebounce = <T,>(value: T, delay: number): T => {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
};

interface RecipientInfo {
  email: string;
  has_device: boolean;
  user_id?: number;
  device_id?: string;
  device_count: number;
}

const ComposeEmail = () => {
  const [recipient, setRecipient] = useState('');
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [encryptionLevel, setEncryptionLevel] = useState<1 | 2 | 3>(1);
  const [sending, setSending] = useState(false);
  const [recipientInfo, setRecipientInfo] = useState<RecipientInfo | null>(null);
  const [checkingRecipient, setCheckingRecipient] = useState(false);

  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

  // Debounce recipient email input (300ms)
  const debouncedRecipient = useDebounce(recipient, 300);

  // Check recipient when debounced value changes
  useEffect(() => {
    const checkRecipient = async () => {
      if (!debouncedRecipient || !debouncedRecipient.includes('@')) {
        setRecipientInfo(null);
        return;
      }

      setCheckingRecipient(true);
      const token = getTokenFromCookie();

      try {
        const response = await fetch(
          `${apiUrl}/device/check-recipient/${encodeURIComponent(debouncedRecipient)}`,
          {
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          }
        );

        if (response.ok) {
          const data: RecipientInfo = await response.json();
          setRecipientInfo(data);

          // Auto-downgrade if Level 2/3 selected but recipient has no device
          if (!data.has_device && (encryptionLevel === 2 || encryptionLevel === 3)) {
            setEncryptionLevel(1);
            toast.warning('Encryption level changed to Level 1', {
              description: 'Recipient has no encryption device registered'
            });
          }
        }
      } catch (error) {
        console.error('Failed to check recipient:', error);
      } finally {
        setCheckingRecipient(false);
      }
    };

    checkRecipient();
  }, [debouncedRecipient, apiUrl]);

  const encryptionLevels = [
    {
      value: 1,
      label: 'Level 1: Normal Gmail',
      description: 'Standard email encryption (TLS only)',
      color: 'bg-gray-100 text-gray-800',
      icon: Shield,
      requiresDevice: false,
    },
    {
      value: 2,
      label: 'Level 2: Post-Quantum (Kyber + AES-GCM)',
      description: 'Quantum-resistant encryption with Kyber algorithm',
      color: 'bg-blue-100 text-blue-800',
      icon: Shield,
      requiresDevice: true,
    },
    {
      value: 3,
      label: 'Level 3: OTP + QKD',
      description: 'One-Time Pad with Quantum Key Distribution (Maximum Security)',
      color: 'bg-purple-100 text-purple-800',
      icon: Shield,
      requiresDevice: true,
    },
  ];

  const isLevelDisabled = (level: number): boolean => {
    if (level === 1) return false;
    return !recipientInfo?.has_device;
  };

  const handleSend = async () => {
    if (!recipient || !subject || !message) {
      toast.error('Please fill in all fields');
      return;
    }

    if ((encryptionLevel === 2 || encryptionLevel === 3) && !recipientInfo?.has_device) {
      toast.error('Cannot send encrypted email', {
        description: 'Recipient must have a registered encryption device'
      });
      return;
    }

    setSending(true);

    try {
      const token = getTokenFromCookie();
      const response = await fetch(`${apiUrl}/api/compose/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        credentials: 'include',
        body: JSON.stringify({
          to: recipient,
          subject: subject,
          message: message,
          encryption_level: encryptionLevel,
          recipient_device_id: recipientInfo?.device_id || null,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to send email');
      }

      const data = await response.json();

      toast.success('Email sent successfully!', {
        description: `Sent with Level ${encryptionLevel} encryption`,
      });

      // Reset form
      setRecipient('');
      setSubject('');
      setMessage('');
      setEncryptionLevel(1);
      setRecipientInfo(null);

    } catch (error) {
      console.error('Send failed:', error);
      toast.error('Failed to send email', {
        description: 'Please try again or contact support',
      });
    } finally {
      setSending(false);
    }
  };

  const getRecipientStatus = () => {
    if (!recipient) return null;
    if (checkingRecipient) {
      return (
        <div className="flex items-center gap-2 text-sm text-muted-foreground animate-pulse">
          <Info className="h-4 w-4" />
          <span>Checking recipient...</span>
        </div>
      );
    }
    if (!recipientInfo) return null;

    if (recipientInfo.has_device) {
      return (
        <div className="flex items-center gap-2 text-sm text-green-600">
          <CheckCircle2 className="h-4 w-4" />
          <span>✓ Recipient has QMail device (Level 2/3 available)</span>
        </div>
      );
    } else {
      return (
        <div className="flex items-center gap-2 text-sm text-yellow-600">
          <AlertCircle className="h-4 w-4" />
          <span>⚠ Recipient has no encryption device (Level 1 only)</span>
        </div>
      );
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
            {/* Recipient Field */}
            <div className="space-y-2">
              <Label htmlFor="recipient">Recipient Email</Label>
              <Input
                id="recipient"
                type="email"
                placeholder="recipient@example.com"
                value={recipient}
                onChange={(e) => setRecipient(e.target.value)}
              />
              {getRecipientStatus()}
            </div>

            {/* Subject Field */}
            <div className="space-y-2">
              <Label htmlFor="subject">Subject</Label>
              <Input
                id="subject"
                placeholder="Enter email subject"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
              />
            </div>

            {/* Message Field */}
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

            {/* Encryption Level Selector */}
            <div className="space-y-3">
              <Label>Encryption Level</Label>
              <div className="grid gap-3">
                {encryptionLevels.map((level) => {
                  const Icon = level.icon;
                  const disabled = isLevelDisabled(level.value);
                  const isSelected = encryptionLevel === level.value;

                  return (
                    <button
                      key={level.value}
                      onClick={() => !disabled && setEncryptionLevel(level.value as 1 | 2 | 3)}
                      disabled={disabled}
                      className={`relative flex items-start gap-3 rounded-lg border-2 p-4 text-left transition-all ${
                        isSelected
                          ? 'border-primary bg-primary/5'
                          : disabled
                          ? 'border-gray-200 bg-gray-50 cursor-not-allowed opacity-50'
                          : 'border-gray-200 hover:border-primary/50 hover:bg-gray-50'
                      }`}
                    >
                      <Icon className={`h-5 w-5 mt-0.5 ${isSelected ? 'text-primary' : 'text-muted-foreground'}`} />
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{level.label}</span>
                          {disabled && level.requiresDevice && (
                            <Badge variant="secondary" className="text-xs">
                              Requires Device
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">{level.description}</p>
                      </div>
                      {isSelected && (
                        <div className="absolute right-4 top-4">
                          <CheckCircle2 className="h-5 w-5 text-primary" />
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Send Button */}
            <Button
              onClick={handleSend}
              disabled={sending || checkingRecipient}
              className="w-full"
              size="lg"
            >
              {sending ? (
                <>
                  <div className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                  Sending...
                </>
              ) : (
                <>
                  <Send className="mr-2 h-4 w-4" />
                  Send Email
                </>
              )}
            </Button>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default ComposeEmail;
