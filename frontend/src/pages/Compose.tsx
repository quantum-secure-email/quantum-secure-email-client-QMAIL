/**
 * Compose Email Component - Updated with Group Support
 * Supports sending to individuals OR groups with Level 1/2 encryption
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { Send, Shield, Users, Mail } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

interface Group {
  id: number;
  name: string;
  member_count: number;
}

export default function Compose() {
  const navigate = useNavigate();
  
  // Recipient type: 'individual' or 'group'
  const [recipientType, setRecipientType] = useState<'individual' | 'group'>('individual');
  
  // Individual recipient
  const [to, setTo] = useState('');
  const [recipientAvailableLevels, setRecipientAvailableLevels] = useState<number[]>([1]);
  
  // Group recipient
  const [groups, setGroups] = useState<Group[]>([]);
  const [selectedGroupId, setSelectedGroupId] = useState<number | null>(null);
  const [groupAvailableLevels, setGroupAvailableLevels] = useState<number[]>([1]);
  
  // Email content
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [encryptionLevel, setEncryptionLevel] = useState<number>(1);
  
  // UI state
  const [sending, setSending] = useState(false);
  const [checkingRecipient, setCheckingRecipient] = useState(false);

  // Fetch groups on mount
  useEffect(() => {
    fetchGroups();
  }, []);

  // Check recipient when email changes
  useEffect(() => {
    if (recipientType === 'individual' && to.includes('@')) {
      checkRecipient(to);
    }
  }, [to]);

  // Check group encryption levels when group changes
  useEffect(() => {
    if (recipientType === 'group' && selectedGroupId) {
      checkGroupEncryptionLevels(selectedGroupId);
    }
  }, [selectedGroupId]);

  const fetchGroups = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/groups`, {
        credentials: 'include'
      });

      if (response.ok) {
        const data = await response.json();
        setGroups(data);
      }
    } catch (error) {
      console.error('Error fetching groups:', error);
    }
  };

  const checkRecipient = async (email: string) => {
    if (!email.includes('@')) return;

    setCheckingRecipient(true);
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/compose/check-recipient?email=${encodeURIComponent(email)}`,
        {
          credentials: 'include'
        }
      );

      if (response.ok) {
        const data = await response.json();
        setRecipientAvailableLevels(data.available_levels);
        
        // Reset encryption level if current is not available
        if (!data.available_levels.includes(encryptionLevel)) {
          setEncryptionLevel(1);
        }
      }
    } catch (error) {
      console.error('Error checking recipient:', error);
    } finally {
      setCheckingRecipient(false);
    }
  };

  const checkGroupEncryptionLevels = async (groupId: number) => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/compose/groups/${groupId}/available-levels`,
        {
          credentials: 'include'
        }
      );

      if (response.ok) {
        const data = await response.json();
        setGroupAvailableLevels(data.available_levels);
        
        // Reset encryption level if current is not available
        if (!data.available_levels.includes(encryptionLevel)) {
          setEncryptionLevel(1);
        }
      }
    } catch (error) {
      console.error('Error checking group levels:', error);
    }
  };

  const handleSend = async () => {
    // Validation
    if (recipientType === 'individual' && !to.trim()) {
      toast.error('Please enter recipient email');
      return;
    }

    if (recipientType === 'group' && !selectedGroupId) {
      toast.error('Please select a group');
      return;
    }

    if (!subject.trim()) {
      toast.error('Please enter a subject');
      return;
    }

    if (!body.trim()) {
      toast.error('Please enter email body');
      return;
    }

    setSending(true);
    try {
      const payload: any = {
        subject,
        body,
        encryption_level: encryptionLevel
      };

      if (recipientType === 'individual') {
        payload.to = to.trim();
      } else {
        payload.group_id = selectedGroupId;
      }

      const response = await fetch(`${API_BASE_URL}/api/compose/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        const result = await response.json();
        
        if (recipientType === 'group') {
          toast.success(`Group email sent to ${result.group_name}!`);
        } else {
          toast.success('Email sent successfully!');
        }
        
        // Reset form
        setTo('');
        setSubject('');
        setBody('');
        setEncryptionLevel(1);
        setSelectedGroupId(null);
        
        // Navigate to inbox after 1 second
        setTimeout(() => navigate('/inbox'), 1000);
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to send email');
      }
    } catch (error) {
      console.error('Error sending email:', error);
      toast.error('Error sending email');
    } finally {
      setSending(false);
    }
  };

  const getEncryptionBadge = (level: number) => {
    switch (level) {
      case 1:
        return <Badge variant="secondary">🔓 Plain</Badge>;
      case 2:
        return <Badge variant="default">🔒 Quantum-Secure</Badge>;
      case 3:
        return <Badge variant="destructive">🔐 Maximum Security</Badge>;
      default:
        return null;
    }
  };

  const availableLevels = recipientType === 'individual' 
    ? recipientAvailableLevels 
    : groupAvailableLevels;

  return (
    <div className="container mx-auto p-6 max-w-4xl">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Send className="h-6 w-6" />
            Compose Email
          </CardTitle>
          <CardDescription>
            Send encrypted emails to individuals or groups
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Recipient Type Selection */}
          <div>
            <Label>Send To</Label>
            <RadioGroup
              value={recipientType}
              onValueChange={(value) => {
                setRecipientType(value as 'individual' | 'group');
                setEncryptionLevel(1);
              }}
              className="flex gap-4 mt-2"
            >
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="individual" id="individual" />
                <Label htmlFor="individual" className="flex items-center gap-2 cursor-pointer">
                  <Mail className="h-4 w-4" />
                  Individual
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="group" id="group" />
                <Label htmlFor="group" className="flex items-center gap-2 cursor-pointer">
                  <Users className="h-4 w-4" />
                  Group
                </Label>
              </div>
            </RadioGroup>
          </div>

          {/* Individual Recipient */}
          {recipientType === 'individual' && (
            <div>
              <Label>To</Label>
              <Input
                type="email"
                placeholder="recipient@example.com"
                value={to}
                onChange={(e) => setTo(e.target.value)}
                className="mt-2"
              />
              {checkingRecipient && (
                <p className="text-sm text-gray-500 mt-1">Checking recipient...</p>
              )}
            </div>
          )}

          {/* Group Recipient */}
          {recipientType === 'group' && (
            <div>
              <Label>Group</Label>
              <Select
                value={selectedGroupId?.toString()}
                onValueChange={(value) => setSelectedGroupId(parseInt(value))}
              >
                <SelectTrigger className="mt-2">
                  <SelectValue placeholder="Select a group" />
                </SelectTrigger>
                <SelectContent>
                  {groups.length === 0 ? (
                    <div className="p-4 text-center text-sm text-gray-500">
                      No groups available. Create one first!
                    </div>
                  ) : (
                    groups.map((group) => (
                      <SelectItem key={group.id} value={group.id.toString()}>
                        <div className="flex items-center gap-2">
                          <Users className="h-4 w-4" />
                          <span>{group.name}</span>
                          <span className="text-gray-500 text-xs">
                            ({group.member_count} members)
                          </span>
                        </div>
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>
            </div>
          )}

          {/* Subject */}
          <div>
            <Label>Subject</Label>
            <Input
              placeholder="Email subject"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              className="mt-2"
            />
          </div>

          {/* Encryption Level */}
          <div>
            <Label>Encryption Level</Label>
            <Select
              value={encryptionLevel.toString()}
              onValueChange={(value) => setEncryptionLevel(parseInt(value))}
            >
              <SelectTrigger className="mt-2">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {availableLevels.includes(1) && (
                  <SelectItem value="1">
                    <div className="flex items-center justify-between w-full gap-4">
                      <span>Level 1 - Plain</span>
                      <Badge variant="secondary">🔓</Badge>
                    </div>
                  </SelectItem>
                )}
                {availableLevels.includes(2) && (
                  <SelectItem value="2">
                    <div className="flex items-center justify-between w-full gap-4">
                      <span>Level 2 - Quantum-Secure (Kyber512 + AES)</span>
                      <Badge>🔒</Badge>
                    </div>
                  </SelectItem>
                )}
                {recipientType === 'individual' && availableLevels.includes(3) && (
                  <SelectItem value="3">
                    <div className="flex items-center justify-between w-full gap-4">
                      <span>Level 3 - Maximum Security (OTP)</span>
                      <Badge variant="destructive">🔐</Badge>
                    </div>
                  </SelectItem>
                )}
              </SelectContent>
            </Select>
            
            <div className="mt-2 p-3 bg-blue-50 rounded-lg">
              <p className="text-sm text-blue-800">
                {encryptionLevel === 1 && '📧 Standard email - visible in Gmail'}
                {encryptionLevel === 2 && '🛡️ Quantum-resistant encryption - appears as gibberish in Gmail'}
                {encryptionLevel === 3 && '🔐 Information-theoretic security - maximum protection'}
                {recipientType === 'group' && encryptionLevel === 2 && ' (shared group key)'}
              </p>
            </div>
          </div>

          {/* Body */}
          <div>
            <Label>Message</Label>
            <Textarea
              placeholder="Type your message here..."
              value={body}
              onChange={(e) => setBody(e.target.value)}
              className="mt-2 min-h-[200px]"
            />
          </div>

          {/* Send Button */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-green-600" />
              <span className="text-sm text-gray-600">
                {getEncryptionBadge(encryptionLevel)}
              </span>
            </div>

            <Button
              onClick={handleSend}
              disabled={sending || (recipientType === 'individual' && !to) || (recipientType === 'group' && !selectedGroupId)}
              size="lg"
            >
              <Send className="h-4 w-4 mr-2" />
              {sending ? 'Sending...' : 'Send Email'}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
