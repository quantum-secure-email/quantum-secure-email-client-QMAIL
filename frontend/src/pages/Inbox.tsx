import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import DashboardLayout from '@/components/DashboardLayout';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Mail, Lock, Shield, Users, RefreshCw } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface Email {
  id: string;
  subject: string;
  from: string;
  to: string;
  date: string;
  snippet: string;
  encryption_type: string;
  body: string;
}

const Inbox = () => {
  const [emails, setEmails] = useState<Email[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEmail, setSelectedEmail] = useState<Email | null>(null);
  const { toast } = useToast();
  const navigate = useNavigate();
  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

  const fetchEmails = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${apiUrl}/api/inbox`, {
        credentials: 'include'
      });

      if (response.status === 401) {
        navigate('/');
        return;
      }

      if (!response.ok) throw new Error('Failed to fetch emails');

      const data = await response.json();
      setEmails(data.messages || []);
    } catch (error) {
      console.error('Error fetching emails:', error);
      toast({
        title: 'Error',
        description: 'Failed to load inbox',
        variant: 'destructive'
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEmails();
  }, []);

  const getEncryptionBadge = (type: string) => {
    switch (type) {
      case 'level2':
        return (
          <Badge className="bg-blue-500">
            <Lock className="w-3 h-3 mr-1" />
            Level 2
          </Badge>
        );
      case 'level3':
        return (
          <Badge className="bg-purple-500">
            <Shield className="w-3 h-3 mr-1" />
            Level 3
          </Badge>
        );
      case 'group_level2':
        return (
          <Badge className="bg-green-500">
            <Users className="w-3 h-3 mr-1" />
            Group
          </Badge>
        );
      default:
        return (
          <Badge variant="outline">
            <Mail className="w-3 h-3 mr-1" />
            Plain
          </Badge>
        );
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-4">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold">Inbox</h1>
            <p className="text-muted-foreground">Your encrypted emails</p>
          </div>
          <Button onClick={fetchEmails} disabled={loading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>

        {loading ? (
          <div className="flex justify-center items-center h-64">
            <RefreshCw className="w-8 h-8 animate-spin text-primary" />
          </div>
        ) : (
          <div className="grid gap-4">
            {emails.length === 0 ? (
              <Card className="p-8 text-center">
                <Mail className="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
                <h3 className="text-lg font-semibold mb-2">No emails</h3>
                <p className="text-muted-foreground">
                  Your inbox is empty. Send yourself a test email to get started!
                </p>
              </Card>
            ) : (
              emails.map((email) => (
                <Card
                  key={email.id}
                  className="p-4 hover:bg-accent cursor-pointer transition-colors"
                  onClick={() => setSelectedEmail(email)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        {getEncryptionBadge(email.encryption_type)}
                        <span className="font-semibold">{email.from}</span>
                      </div>
                      <h3 className="font-medium mb-1">{email.subject}</h3>
                      <p className="text-sm text-muted-foreground line-clamp-2">
                        {email.snippet}
                      </p>
                    </div>
                    <div className="text-sm text-muted-foreground ml-4">
                      {new Date(email.date).toLocaleDateString()}
                    </div>
                  </div>
                </Card>
              ))
            )}
          </div>
        )}

        {/* Email Detail Modal */}
        {selectedEmail && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
            <Card className="max-w-2xl w-full max-h-[80vh] overflow-y-auto">
              <div className="p-6">
                <div className="flex justify-between items-start mb-4">
                  <div className="flex-1">
                    {getEncryptionBadge(selectedEmail.encryption_type)}
                    <h2 className="text-2xl font-bold mt-2">{selectedEmail.subject}</h2>
                    <p className="text-muted-foreground mt-1">
                      From: {selectedEmail.from}
                    </p>
                    <p className="text-muted-foreground">
                      Date: {new Date(selectedEmail.date).toLocaleString()}
                    </p>
                  </div>
                  <Button variant="ghost" onClick={() => setSelectedEmail(null)}>
                    Close
                  </Button>
                </div>

                <div className="prose max-w-none">
                  <pre className="whitespace-pre-wrap bg-muted p-4 rounded-lg">
                    {selectedEmail.body}
                  </pre>
                </div>

                {selectedEmail.encryption_type !== 'plain' && (
                  <div className="mt-4 p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                    <p className="text-sm">
                      <strong>Note:</strong> This is an encrypted message. Client-side
                      decryption will be implemented in the next phase.
                    </p>
                  </div>
                )}
              </div>
            </Card>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default Inbox;
