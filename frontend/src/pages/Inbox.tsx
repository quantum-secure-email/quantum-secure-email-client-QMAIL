/**
 * Inbox Component - Updated with Group Email Decryption
 * Handles Level 2, Level 3, and Group Level 2 encrypted emails
 */

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { Mail, Lock, Unlock, Users, Shield, Loader2 } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Separator } from '@/components/ui/separator';
import { decryptEmail, detectEncryptionType } from '@/utils/decryptionUtils';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

interface Email {
  id: string;
  from: string;
  to: string[];
  subject: string;
  snippet: string;
  body: string;
  date: string;
  labels: string[];
  isRead: boolean;
  encryption_level?: number;
  isGroupEmail?: boolean;
  groupName?: string;
  groupId?: number;
}

export default function Inbox() {
  const [emails, setEmails] = useState<Email[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEmail, setSelectedEmail] = useState<Email | null>(null);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptedBody, setDecryptedBody] = useState<string>('');
  const [dialogOpen, setDialogOpen] = useState(false);

  useEffect(() => {
    fetchInbox();
  }, []);

  const fetchInbox = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/inbox?primary_only=true`, {
        credentials: 'include'
      });

      if (response.ok) {
        const data = await response.json();
        const processedEmails = data.messages.map((email: any) => {
          const encryptionType = detectEncryptionType(email.body);
          const isGroupEmail = encryptionType === 'group_level2';
          
          let groupName, groupId;
          if (isGroupEmail) {
            const groupNameMatch = email.body.match(/group_name:\s*([^\n]+)/);
            const groupIdMatch = email.body.match(/group_id:\s*(\d+)/);
            groupName = groupNameMatch ? groupNameMatch[1].trim() : 'Unknown Group';
            groupId = groupIdMatch ? parseInt(groupIdMatch[1]) : null;
          }
          
          return {
            ...email,
            encryption_level: encryptionType === 'plain' ? 1 : 2,
            isGroupEmail,
            groupName,
            groupId
          };
        });
        
        setEmails(processedEmails);
      } else {
        toast.error('Failed to fetch inbox');
      }
    } catch (error) {
      console.error('Error fetching inbox:', error);
      toast.error('Error loading inbox');
    } finally {
      setLoading(false);
    }
  };

  const handleEmailClick = async (email: Email) => {
    setSelectedEmail(email);
    setDialogOpen(true);
    setDecryptedBody('');
    
    // Mark as read
    try {
      await fetch(`${API_BASE_URL}/api/inbox/${email.id}/read`, {
        method: 'POST',
        credentials: 'include'
      });
    } catch (error) {
      console.error('Error marking as read:', error);
    }

    // Decrypt if encrypted
    if (email.encryption_level && email.encryption_level > 1) {
      await decryptEmailContent(email);
    } else {
      setDecryptedBody(email.body);
    }
  };

  const decryptEmailContent = async (email: Email) => {
    setDecrypting(true);
    try {
      const plaintext = await decryptEmail(email.body);
      setDecryptedBody(plaintext);
      toast.success('Email decrypted successfully!');
    } catch (error) {
      console.error('Decryption error:', error);
      toast.error('Failed to decrypt email. Make sure your device is set up.');
      setDecryptedBody('❌ Decryption failed. Please check your device setup.');
    } finally {
      setDecrypting(false);
    }
  };

  const getEncryptionBadge = (email: Email) => {
    if (email.isGroupEmail) {
      return (
        <Badge variant="default" className="flex items-center gap-1">
          <Users className="h-3 w-3" />
          Group
        </Badge>
      );
    }
    
    if (email.encryption_level === 2) {
      return (
        <Badge variant="default" className="flex items-center gap-1">
          <Lock className="h-3 w-3" />
          Encrypted
        </Badge>
      );
    }
    
    if (email.encryption_level === 3) {
      return (
        <Badge variant="destructive" className="flex items-center gap-1">
          <Shield className="h-3 w-3" />
          OTP
        </Badge>
      );
    }
    
    return (
      <Badge variant="secondary" className="flex items-center gap-1">
        <Unlock className="h-3 w-3" />
        Plain
      </Badge>
    );
  };

  if (loading) {
    return (
      <div className="container mx-auto p-6 max-w-6xl">
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin" />
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Mail className="h-8 w-8" />
            Inbox
          </h1>
          <p className="text-gray-500 mt-1">{emails.length} messages</p>
        </div>
        
        <Button onClick={fetchInbox}>Refresh</Button>
      </div>

      {/* Email List */}
      <div className="space-y-2">
        {emails.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Mail className="h-16 w-16 text-gray-300 mb-4" />
              <p className="text-gray-500">No emails found</p>
            </CardContent>
          </Card>
        ) : (
          emails.map((email) => (
            <Card
              key={email.id}
              className={`cursor-pointer hover:shadow-md transition-shadow ${
                !email.isRead ? 'border-l-4 border-l-blue-500' : ''
              }`}
              onClick={() => handleEmailClick(email)}
            >
              <CardHeader className="py-4">
                <div className="flex justify-between items-start">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <CardTitle className="text-lg truncate">
                        {email.subject || '(No Subject)'}
                      </CardTitle>
                      {getEncryptionBadge(email)}
                      {email.isGroupEmail && (
                        <Badge variant="outline">{email.groupName}</Badge>
                      )}
                    </div>
                    <CardDescription className="flex items-center gap-2">
                      <span className="font-medium">{email.from}</span>
                      <span>·</span>
                      <span>{new Date(email.date).toLocaleString()}</span>
                    </CardDescription>
                  </div>
                  
                  {!email.isRead && (
                    <Badge variant="default">New</Badge>
                  )}
                </div>
                
                <p className="text-sm text-gray-600 truncate mt-2">
                  {email.snippet}
                </p>
              </CardHeader>
            </Card>
          ))
        )}
      </div>

      {/* Email Detail Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          {selectedEmail && (
            <>
              <DialogHeader>
                <div className="flex items-center gap-2">
                  <DialogTitle className="text-2xl">
                    {selectedEmail.subject || '(No Subject)'}
                  </DialogTitle>
                  {getEncryptionBadge(selectedEmail)}
                </div>
                
                <div className="flex items-center gap-4 text-sm text-gray-600 mt-2">
                  <div>
                    <span className="font-medium">From:</span> {selectedEmail.from}
                  </div>
                  <div>
                    <span className="font-medium">To:</span> {selectedEmail.to.join(', ')}
                  </div>
                  <div>
                    <span className="font-medium">Date:</span>{' '}
                    {new Date(selectedEmail.date).toLocaleString()}
                  </div>
                </div>
                
                {selectedEmail.isGroupEmail && (
                  <div className="mt-2 p-3 bg-blue-50 rounded-lg flex items-center gap-2">
                    <Users className="h-5 w-5 text-blue-600" />
                    <span className="text-sm text-blue-800">
                      Group Message: <strong>{selectedEmail.groupName}</strong>
                    </span>
                  </div>
                )}
              </DialogHeader>

              <Separator className="my-4" />

              {/* Email Body */}
              <div className="mt-4">
                {decrypting ? (
                  <div className="flex items-center justify-center py-12">
                    <div className="text-center">
                      <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
                      <p className="text-gray-600">Decrypting email...</p>
                      {selectedEmail.isGroupEmail && (
                        <p className="text-sm text-gray-500 mt-2">
                          Fetching group key...
                        </p>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="prose max-w-none">
                    <pre className="whitespace-pre-wrap font-sans text-sm bg-gray-50 p-4 rounded-lg">
                      {decryptedBody || selectedEmail.body}
                    </pre>
                  </div>
                )}
              </div>

              {/* Encryption Info */}
              {selectedEmail.encryption_level && selectedEmail.encryption_level > 1 && (
                <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-lg">
                  <div className="flex items-center gap-2 text-green-800">
                    <Shield className="h-5 w-5" />
                    <span className="font-medium">
                      {selectedEmail.isGroupEmail 
                        ? 'Group encryption verified' 
                        : 'End-to-end encryption verified'}
                    </span>
                  </div>
                  <p className="text-sm text-green-700 mt-1">
                    {selectedEmail.isGroupEmail
                      ? 'This message was encrypted with your group\'s shared key'
                      : 'This message was encrypted with quantum-resistant cryptography'}
                  </p>
                </div>
              )}
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
