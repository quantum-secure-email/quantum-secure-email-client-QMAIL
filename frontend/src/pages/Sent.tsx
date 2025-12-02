
import { useState, useEffect } from 'react';
import DashboardLayout from '@/components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Send, Shield, Lock, Mail } from 'lucide-react';
import { toast } from 'sonner';
import { format } from 'date-fns';

interface SentEmail {
  id: string;
  to: string;
  subject: string;
  snippet: string;
  date: string;
  encryption_level: 1 | 2 | 3;
}

const getAuthToken = (): string | null => {
  return localStorage.getItem('auth_token');
};

const SentPage = () => {
  const [sentEmails, setSentEmails] = useState<SentEmail[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEmail, setSelectedEmail] = useState<SentEmail | null>(null);

  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

  useEffect(() => {
    fetchSentEmails();
  }, []);

  const fetchSentEmails = async () => {
    try {
      const token = getAuthToken();
      const response = await fetch(`${apiUrl}/api/sent`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch sent emails');
      }

      const data = await response.json();
      setSentEmails(data.emails || data.messages || []);
    } catch (error) {
      console.error('Failed to fetch sent emails:', error);
      toast.error('Failed to load sent emails');
    } finally {
      setLoading(false);
    }
  };

  const getEncryptionBadge = (level: 1 | 2 | 3) => {
    switch (level) {
      case 1:
        return (
          <Badge variant="secondary" className="flex items-center gap-1">
            <Mail className="h-3 w-3" />
            Level 1
          </Badge>
        );
      case 2:
        return (
          <Badge className="flex items-center gap-1 bg-blue-600">
            <Shield className="h-3 w-3" />
            Level 2 (Kyber)
          </Badge>
        );
      case 3:
        return (
          <Badge className="flex items-center gap-1 bg-purple-600">
            <Lock className="h-3 w-3" />
            Level 3 (OTP)
          </Badge>
        );
    }
  };

  return (
    <DashboardLayout>
      <div className="mx-auto max-w-6xl space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Sent</h1>
          <p className="text-muted-foreground">
            View your sent emails and their encryption levels
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Send className="h-5 w-5" />
              Sent Messages
            </CardTitle>
            <CardDescription>
              {sentEmails.length} messages sent
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              </div>
            ) : sentEmails.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <Send className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No sent emails yet</p>
                <p className="text-sm">Start by composing your first encrypted email</p>
              </div>
            ) : (
              <div className="space-y-2">
                {sentEmails.map((email) => (
                  <div
                    key={email.id}
                    onClick={() => setSelectedEmail(email)}
                    className="flex items-center gap-4 p-4 rounded-lg border hover:bg-gray-50 cursor-pointer transition-colors"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-1">
                        <p className="text-sm font-medium text-foreground truncate">
                          To: {email.to}
                        </p>
                        {getEncryptionBadge(email.encryption_level)}
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
                  {getEncryptionBadge(selectedEmail.encryption_level)}
                </div>
                <CardDescription>
                  To: {selectedEmail.to} • {format(new Date(selectedEmail.date), 'PPpp')}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="prose prose-sm max-w-none">
                  <p className="whitespace-pre-wrap">{selectedEmail.snippet}</p>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default SentPage;
