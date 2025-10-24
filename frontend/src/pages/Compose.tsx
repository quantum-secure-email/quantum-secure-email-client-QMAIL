import { useState } from 'react';
import DashboardLayout from '@/components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Shield, Send, Info } from 'lucide-react';
import { toast } from 'sonner';

const Compose = () => {
  const [recipient, setRecipient] = useState('');
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [encryptionLevel, setEncryptionLevel] = useState('1');
  const [sending, setSending] = useState(false);

  const encryptionLevels = [
    {
      value: '1',
      label: 'Level 1: Normal Gmail',
      description: 'Standard email encryption',
      color: 'text-muted-foreground',
    },
    {
      value: '2',
      label: 'Level 2: Post-Quantum (Kyber + AES-GCM)',
      description: 'Quantum-resistant encryption with Kyber algorithm',
      color: 'text-primary',
    },
    {
      value: '3',
      label: 'Level 3: OTP + QKD',
      description: 'One-Time Pad with Quantum Key Distribution',
      color: 'text-accent',
    },
  ];

  const selectedLevel = encryptionLevels.find((level) => level.value === encryptionLevel);

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

    setSending(true);

    try {
      // Mock API call - replace with actual endpoint
      const response = await fetch('/api/send-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          recipient,
          subject,
          message,
          encryptionLevel,
        }),
      });

      // Since this is a mock, we'll simulate success
      setTimeout(() => {
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
        setSending(false);
      }, 1500);
    } catch (error) {
      console.error('Error sending email:', error);
      toast.error('Failed to send email. Please try again.');
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
              />
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
                    <SelectItem key={level.value} value={level.value}>
                      {level.label}
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
                disabled={sending}
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
              <strong className="text-foreground">Level 1:</strong> Uses standard email
              encryption. Suitable for non-sensitive communications.
            </p>
            <p>
              <strong className="text-foreground">Level 2:</strong> Implements post-quantum
              cryptography using the Kyber algorithm, protecting against future quantum attacks.
            </p>
            <p>
              <strong className="text-foreground">Level 3:</strong> Maximum security using
              One-Time Pad encryption with Quantum Key Distribution for unbreakable encryption.
            </p>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default Compose;
