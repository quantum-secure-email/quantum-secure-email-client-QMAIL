/**
 * Groups Management Component
 * Create, view, and manage encrypted groups
 */

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { 
  Users, 
  Plus, 
  Trash2, 
  UserPlus, 
  LogOut,
  Shield,
  Mail
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

interface Group {
  id: number;
  name: string;
  created_by: number;
  creator_email: string;
  member_count: number;
  created_at: string;
  updated_at: string;
  is_creator: boolean;
}

interface GroupMember {
  user_id: number;
  email: string;
  name: string | null;
  joined_at: string;
}

export default function GroupsManager() {
  const [groups, setGroups] = useState<Group[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<Group | null>(null);
  const [members, setMembers] = useState<GroupMember[]>([]);
  const [loading, setLoading] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [addMemberDialogOpen, setAddMemberDialogOpen] = useState(false);
  
  // Create group form
  const [newGroupName, setNewGroupName] = useState('');
  const [newMemberEmails, setNewMemberEmails] = useState('');
  
  // Add member form
  const [memberEmail, setMemberEmail] = useState('');

  useEffect(() => {
    fetchGroups();
  }, []);

  useEffect(() => {
    if (selectedGroup) {
      fetchGroupMembers(selectedGroup.id);
    }
  }, [selectedGroup]);

  const fetchGroups = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/groups`, {
        credentials: 'include'
      });

      if (response.ok) {
        const data = await response.json();
        setGroups(data);
      } else {
        toast.error('Failed to fetch groups');
      }
    } catch (error) {
      console.error('Error fetching groups:', error);
      toast.error('Error loading groups');
    }
  };

  const fetchGroupMembers = async (groupId: number) => {
    try {
      const response = await fetch(`${API_BASE_URL}/groups/${groupId}/members`, {
        credentials: 'include'
      });

      if (response.ok) {
        const data = await response.json();
        setMembers(data);
      } else {
        toast.error('Failed to fetch group members');
      }
    } catch (error) {
      console.error('Error fetching members:', error);
    }
  };

  const handleCreateGroup = async () => {
    if (!newGroupName.trim()) {
      toast.error('Please enter a group name');
      return;
    }

    setLoading(true);
    try {
      // Parse member emails
      const memberEmails = newMemberEmails
        .split(',')
        .map(email => email.trim())
        .filter(email => email.length > 0);

      const response = await fetch(`${API_BASE_URL}/groups`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({
          name: newGroupName,
          member_emails: memberEmails
        })
      });

      if (response.ok) {
        const newGroup = await response.json();
        toast.success(`Group "${newGroup.name}" created successfully!`);
        setGroups([...groups, newGroup]);
        setNewGroupName('');
        setNewMemberEmails('');
        setCreateDialogOpen(false);
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to create group');
      }
    } catch (error) {
      console.error('Error creating group:', error);
      toast.error('Error creating group');
    } finally {
      setLoading(false);
    }
  };

  const handleAddMember = async () => {
    if (!selectedGroup) return;
    if (!memberEmail.trim()) {
      toast.error('Please enter an email address');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/groups/${selectedGroup.id}/members`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({
          email: memberEmail.trim()
        })
      });

      if (response.ok) {
        toast.success(`${memberEmail} added to group!`);
        setMemberEmail('');
        setAddMemberDialogOpen(false);
        fetchGroupMembers(selectedGroup.id);
        fetchGroups(); // Refresh group list to update member counts
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to add member');
      }
    } catch (error) {
      console.error('Error adding member:', error);
      toast.error('Error adding member');
    } finally {
      setLoading(false);
    }
  };

  const handleLeaveGroup = async (groupId: number) => {
    if (!window.confirm('Are you sure you want to leave this group?')) {
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/groups/${groupId}/members/me`, {
        method: 'DELETE',
        credentials: 'include'
      });

      if (response.ok) {
        toast.success('Successfully left the group');
        setGroups(groups.filter(g => g.id !== groupId));
        setSelectedGroup(null);
        setMembers([]);
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to leave group');
      }
    } catch (error) {
      console.error('Error leaving group:', error);
      toast.error('Error leaving group');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteGroup = async (groupId: number) => {
    if (!window.confirm('Are you sure you want to delete this group? This action cannot be undone.')) {
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/groups/${groupId}`, {
        method: 'DELETE',
        credentials: 'include'
      });

      if (response.ok) {
        toast.success('Group deleted successfully');
        setGroups(groups.filter(g => g.id !== groupId));
        setSelectedGroup(null);
        setMembers([]);
      } else {
        const error = await response.json();
        toast.error(error.detail || 'Failed to delete group');
      }
    } catch (error) {
      console.error('Error deleting group:', error);
      toast.error('Error deleting group');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Users className="h-8 w-8" />
            Groups
          </h1>
          <p className="text-gray-500 mt-1">Manage your encrypted group communications</p>
        </div>
        
        <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Create Group
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create New Group</DialogTitle>
              <DialogDescription>
                Create a quantum-secure encrypted group for private communications
              </DialogDescription>
            </DialogHeader>
            
            <div className="space-y-4 mt-4">
              <div>
                <label className="text-sm font-medium">Group Name</label>
                <Input
                  placeholder="e.g., Team Alpha, Family"
                  value={newGroupName}
                  onChange={(e) => setNewGroupName(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleCreateGroup()}
                />
              </div>
              
              <div>
                <label className="text-sm font-medium">Initial Members (optional)</label>
                <Input
                  placeholder="email1@example.com, email2@example.com"
                  value={newMemberEmails}
                  onChange={(e) => setNewMemberEmails(e.target.value)}
                />
                <p className="text-xs text-gray-500 mt-1">
                  Comma-separated email addresses. You can add more members later.
                </p>
              </div>
              
              <Button 
                onClick={handleCreateGroup} 
                disabled={loading}
                className="w-full"
              >
                {loading ? 'Creating...' : 'Create Group'}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Groups Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-8">
        {groups.length === 0 ? (
          <Card className="col-span-full">
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Users className="h-16 w-16 text-gray-300 mb-4" />
              <p className="text-gray-500 text-center">
                No groups yet. Create one to start encrypted group conversations!
              </p>
            </CardContent>
          </Card>
        ) : (
          groups.map(group => (
            <Card
              key={group.id}
              className={`cursor-pointer hover:shadow-lg transition-shadow ${
                selectedGroup?.id === group.id ? 'ring-2 ring-blue-500' : ''
              }`}
              onClick={() => setSelectedGroup(group)}
            >
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span className="truncate">{group.name}</span>
                  {group.is_creator && (
                    <Badge variant="secondary">Creator</Badge>
                  )}
                </CardTitle>
                <CardDescription>
                  Created by {group.creator_email}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <Users className="h-4 w-4" />
                    <span>{group.member_count} members</span>
                  </div>
                  <div className="flex items-center gap-1 text-green-600">
                    <Shield className="h-4 w-4" />
                    <span className="text-xs">Encrypted</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {/* Group Details */}
      {selectedGroup && (
        <Card>
          <CardHeader>
            <div className="flex justify-between items-start">
              <div>
                <CardTitle className="text-2xl">{selectedGroup.name}</CardTitle>
                <CardDescription>
                  {selectedGroup.member_count} members · Created {new Date(selectedGroup.created_at).toLocaleDateString()}
                </CardDescription>
              </div>
              
              <div className="flex gap-2">
                {selectedGroup.is_creator && (
                  <>
                    <Dialog open={addMemberDialogOpen} onOpenChange={setAddMemberDialogOpen}>
                      <DialogTrigger asChild>
                        <Button variant="outline" size="sm">
                          <UserPlus className="h-4 w-4 mr-2" />
                          Add Member
                        </Button>
                      </DialogTrigger>
                      <DialogContent>
                        <DialogHeader>
                          <DialogTitle>Add Member to {selectedGroup.name}</DialogTitle>
                          <DialogDescription>
                            Add a QMail user to this encrypted group
                          </DialogDescription>
                        </DialogHeader>
                        
                        <div className="space-y-4 mt-4">
                          <div>
                            <label className="text-sm font-medium">Email Address</label>
                            <Input
                              type="email"
                              placeholder="user@example.com"
                              value={memberEmail}
                              onChange={(e) => setMemberEmail(e.target.value)}
                              onKeyPress={(e) => e.key === 'Enter' && handleAddMember()}
                            />
                          </div>
                          
                          <Button 
                            onClick={handleAddMember} 
                            disabled={loading}
                            className="w-full"
                          >
                            {loading ? 'Adding...' : 'Add Member'}
                          </Button>
                        </div>
                      </DialogContent>
                    </Dialog>
                    
                    <Button 
                      variant="destructive" 
                      size="sm"
                      onClick={() => handleDeleteGroup(selectedGroup.id)}
                      disabled={loading}
                    >
                      <Trash2 className="h-4 w-4 mr-2" />
                      Delete Group
                    </Button>
                  </>
                )}
                
                {!selectedGroup.is_creator && (
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => handleLeaveGroup(selectedGroup.id)}
                    disabled={loading}
                  >
                    <LogOut className="h-4 w-4 mr-2" />
                    Leave Group
                  </Button>
                )}
              </div>
            </div>
          </CardHeader>
          
          <Separator />
          
          <CardContent className="mt-6">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <Users className="h-5 w-5" />
              Members
            </h3>
            
            <div className="space-y-2">
              {members.map(member => (
                <div
                  key={member.user_id}
                  className="flex items-center justify-between p-3 rounded-lg bg-gray-50 hover:bg-gray-100"
                >
                  <div>
                    <p className="font-medium">{member.name || member.email}</p>
                    <p className="text-sm text-gray-500">{member.email}</p>
                    <p className="text-xs text-gray-400">
                      Joined {new Date(member.joined_at).toLocaleDateString()}
                    </p>
                  </div>
                  
                  {member.user_id === selectedGroup.created_by && (
                    <Badge>Creator</Badge>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
