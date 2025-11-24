import { useState, useEffect } from 'react';
import DashboardLayout from '@/components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Mail, Shield, Lock, Loader2, Users } from 'lucide-react';
import { toast } from 'sonner';
import { format } from 'date-fns';
import { decryptEmail, detectEncryptionLevel } from '@/utils/decryptionUtils';

interface Email {
  id: string;
  from: string;
  subject: string;
  snippet: string;
  body: string;
  date: string;
  encryption_level: 1 | 2 | 3 | 'group' | null;
  decrypted?: boolean;
  decrypted_body?: string;
}

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

const InboxUpdated = () => {
  const [emails, setEmails] = useState<Email[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEmail, setSelectedEmail] = useState<Email | null>(null);
  const [decrypting, setDecrypting] = useState(false);

  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchEmails();
  }, []);

  const fetchEmails = async () => {
    try {
      const token = getTokenFromCookie();
      const response = await fetch(`${apiUrl}/api/inbox`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch emails');
      }

      const data = await response.json();
      const emailsWithLevel = (data.emails || data.messages || []).map((email: any) => ({
        ...email,
        encryption_level: detectEncryptionLevel(email.body),
        decrypted: false
      }));
      
      setEmails(emailsWithLevel);
    } catch (error) {
      console.error('Failed to fetch emails:', error);
      toast.error('Failed to load emails');
    } finally {
      setLoading(false);
    }
  };

  const handleDecryptEmail = async (email: Email) => {
    if (email.encryption_level === 1 || email.decrypted) {
      // Already decrypted or not encrypted
      return;
    }

    setDecrypting(true);

    try {
      console.log('🔓 Attempting to decrypt email...');
      console.log('Encryption level:', email.encryption_level);
      
      const decryptedBody = await decryptEmail(email.body);
      
      // Update email with decrypted content
      const updatedEmail = {
        ...email,
        decrypted: true,
        decrypted_body: decryptedBody
      };
      
      setSelectedEmail(updatedEmail);
      
      // Update emails list
      setEmails(emails.map(e => 
        e.id === email.id ? updatedEmail : e
      ));
      
      toast.success('Email decrypted successfully!');
      
    } catch (error) {
      console.error('Decryption failed:', error);
      toast.error('Failed to decrypt email', {
        description: error instanceof Error ? error.message : 'Please check your device setup'
      });
    } finally {
      setDecrypting(false);
    }
  };

  const handleSelectEmail = (email: Email) => {
    setSelectedEmail(email);
    
    // Auto-decrypt if encrypted and not yet decrypted
    if (email.encryption_level && email.encryption_level !== 1 && !email.decrypted) {
      handleDecryptEmail(email);
    }
  };

  const getEncryptionBadge = (level: 1 | 2 | 3 | 'group' | null) => {
    if (!level || level === 1) {
      return (
        <Badge variant="secondary" className="flex items-center gap-1">
          <Mail className="h-3 w-3" />
          Standard
        </Badge>
      );
    }
    
    if (level === 'group') {
      return (
        <Badge className="flex items-center gap-1 bg-blue-600">
          <Users className="h-3 w-3" />
          Level 2 (Group)
        </Badge>
      );
    }
    
    switch (level) {
      case 2:
        return (
          <Badge className="flex items-center gap-1 bg-blue-600">
            <Shield className="h-3 w-3" />
            Level 2 Encrypted
          </Badge>
        );
      case 3:
        return (
          <Badge className="flex items-center gap-1 bg-purple-600">
            <Lock className="h-3 w-3" />
            Level 3 Encrypted
          </Badge>
        );
    }
  };

  const getEmailBody = (email: Email) => {
    if (email.decrypted && email.decrypted_body) {
      return email.decrypted_body;
    }
    
    if (email.encryption_level && email.encryption_level !== 1) {
      return '🔐 This message is encrypted. Click to decrypt...';
    }
    
    return email.body;
  };

  const getEncryptionDescription = (level: 1 | 2 | 3 | 'group' | null) => {
    if (level === 'group') {
      return 'Level 2 (Kyber512 + AES-256-GCM) - Group Message';
    }
    if (level === 2) {
      return 'Level 2 (Kyber512 + AES-256-GCM)';
    }
    if (level === 3) {
      return 'Level 3 (OTP + QKD)';
    }
    return null;
  };

  return (
    <DashboardLayout>
      <div className="mx-auto max-w-6xl space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Inbox</h1>
          <p className="text-muted-foreground">
            Your encrypted and standard emails
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Mail className="h-5 w-5" />
              All Messages
            </CardTitle>
            <CardDescription>
              {emails.length} messages
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              </div>
            ) : emails.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <Mail className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No emails yet</p>
              </div>
            ) : (
              <div className="space-y-2">
                {emails.map((email) => (
                  <div
                    key={email.id}
                    onClick={() => handleSelectEmail(email)}
                    className="flex items-center gap-4 p-4 rounded-lg border hover:bg-gray-50 cursor-pointer transition-colors"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-1">
                        <p className="text-sm font-medium text-foreground truncate">
                          From: {email.from}
                        </p>
                        {getEncryptionBadge(email.encryption_level)}
                        {email.decrypted && (
                          <Badge variant="outline" className="text-green-600">
                            Decrypted ✓
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm font-medium text-foreground mb-1 truncate">
                        {email.subject || '(no subject)'}
                      </p>
                      <p className="text-sm text-muted-foreground truncate">
                        {email.snippet}
                      </p>
                    </div>
                    <div className="text-sm text-muted-foreground whitespace-nowrap">
                      {format(new Date(email.date), 'MMM d, yyyy')}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Email Detail Modal */}
        {selectedEmail && (
          <div
            className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50"
            onClick={() => setSelectedEmail(null)}
          >
            <Card
              className="max-w-2xl w-full max-h-[80vh] overflow-y-auto"
              onClick={(e) => e.stopPropagation()}
            >
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle>{selectedEmail.subject || '(no subject)'}</CardTitle>
                  <div className="flex items-center gap-2">
                    {getEncryptionBadge(selectedEmail.encryption_level)}
                    {selectedEmail.decrypted && (
                      <Badge variant="outline" className="text-green-600">
                        Decrypted ✓
                      </Badge>
                    )}
                  </div>
                </div>
                <CardDescription>
                  From: {selectedEmail.from} • {format(new Date(selectedEmail.date), 'PPpp')}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {selectedEmail.encryption_level && selectedEmail.encryption_level !== 1 && !selectedEmail.decrypted ? (
                  <div className="text-center py-8">
                    <Lock className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                    <p className="text-lg font-medium mb-2">Encrypted Message</p>
                    <p className="text-sm text-muted-foreground mb-4">
                      {getEncryptionDescription(selectedEmail.encryption_level)}
                    </p>
                    <Button 
                      onClick={() => handleDecryptEmail(selectedEmail)}
                      disabled={decrypting}
                    >
                      {decrypting ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Decrypting...
                        </>
                      ) : (
                        'Decrypt Message'
                      )}
                    </Button>
                  </div>
                ) : (
                  <div className="prose prose-sm max-w-none">
                    <p className="whitespace-pre-wrap">{getEmailBody(selectedEmail)}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default InboxUpdated;