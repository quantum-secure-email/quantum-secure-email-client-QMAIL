import { useState, useEffect } from 'react';
import DashboardLayout from '@/components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Users, Plus, UserPlus, Trash2, LogOut, Mail, Shield } from 'lucide-react';
import { toast } from 'sonner';

interface Group {
  id: number;
  name: string;
  created_by: number;
  member_count: number;
  is_creator: boolean;
}

interface GroupMember {
  user_id: number;
  email: string;
  name: string;
  joined_at: string;
  is_creator: boolean;
}

interface GroupDetails {
  id: number;
  name: string;
  created_by: number;
  is_creator: boolean;
  members: GroupMember[];
}

const GroupThreads = () => {
  const [groups, setGroups] = useState<Group[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<GroupDetails | null>(null);
  const [loading, setLoading] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [addMemberDialogOpen, setAddMemberDialogOpen] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [newMemberEmail, setNewMemberEmail] = useState('');

  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

  // Fetch all groups
  const fetchGroups = async () => {
    try {
      const response = await fetch(`${apiUrl}/api/groups/list`, {
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        setGroups(data.groups || []);
      } else {
        console.error('Failed to fetch groups');
      }
    } catch (error) {
      console.error('Error fetching groups:', error);
    }
  };

  // Fetch group details
  const fetchGroupDetails = async (groupId: number) => {
    setLoading(true);
    try {
      const response = await fetch(`${apiUrl}/api/groups/${groupId}`, {
        credentials: 'include',
      });

      if (response.ok) {
        const data = await response.json();
        setSelectedGroup(data);
      } else {
        toast.error('Failed to fetch group details');
      }
    } catch (error) {
      console.error('Error fetching group details:', error);
      toast.error('Error fetching group details');
    } finally {
      setLoading(false);
    }
  };

  // Create new group
  const handleCreateGroup = async () => {
    if (!newGroupName.trim()) {
      toast.error('Please enter a group name');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${apiUrl}/api/groups/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ name: newGroupName }),
      });

      if (response.ok) {
        const data = await response.json();
        toast.success(`Group "${newGroupName}" created successfully!`);
        setNewGroupName('');
        setCreateDialogOpen(false);
        await fetchGroups();
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

  // Add member to group
  const handleAddMember = async () => {
    if (!selectedGroup || !newMemberEmail.trim()) {
      toast.error('Please enter a member email');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${apiUrl}/api/groups/${selectedGroup.id}/members/add`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email: newMemberEmail }),
      });

      if (response.ok) {
        toast.success(`Added ${newMemberEmail} to group!`);
        setNewMemberEmail('');
        setAddMemberDialogOpen(false);
        await fetchGroupDetails(selectedGroup.id);
        await fetchGroups();
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

  // Leave group
  const handleLeaveGroup = async (groupId: number) => {
    if (!confirm('Are you sure you want to leave this group?')) return;

    setLoading(true);
    try {
      const response = await fetch(`${apiUrl}/api/groups/${groupId}/leave`, {
        method: 'DELETE',
        credentials: 'include',
      });

      if (response.ok) {
        toast.success('Left group successfully');
        setSelectedGroup(null);
        await fetchGroups();
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

  // Delete group
  const handleDeleteGroup = async (groupId: number) => {
    if (!confirm('Are you sure you want to delete this group? This action cannot be undone.')) return;

    setLoading(true);
    try {
      const response = await fetch(`${apiUrl}/api/groups/${groupId}`, {
        method: 'DELETE',
        credentials: 'include',
      });

      if (response.ok) {
        toast.success('Group deleted successfully');
        setSelectedGroup(null);
        await fetchGroups();
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

  useEffect(() => {
    fetchGroups();
  }, []);

  return (
    <DashboardLayout>
      <div className="mx-auto max-w-6xl space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground">Groups</h1>
            <p className="text-muted-foreground">
              Manage quantum-secure group communication
            </p>
          </div>
          
          <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Create Group
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create New Group</DialogTitle>
                <DialogDescription>
                  Create a quantum-secure group for team communication
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label htmlFor="group-name">Group Name</Label>
                  <Input
                    id="group-name"
                    placeholder="Enter group name"
                    value={newGroupName}
                    onChange={(e) => setNewGroupName(e.target.value)}
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setCreateDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={handleCreateGroup} disabled={loading}>
                  {loading ? 'Creating...' : 'Create Group'}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        {/* Main Content */}
        <div className="grid gap-6 md:grid-cols-2">
          {/* Groups List */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-5 w-5 text-primary" />
                Your Groups
              </CardTitle>
              <CardDescription>
                {groups.length} {groups.length === 1 ? 'group' : 'groups'}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {groups.length === 0 ? (
                <div className="rounded-lg border border-dashed border-border p-8 text-center">
                  <Users className="mx-auto mb-2 h-8 w-8 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">
                    No groups yet. Create your first group!
                  </p>
                </div>
              ) : (
                groups.map((group) => (
                  <div
                    key={group.id}
                    className={`cursor-pointer rounded-lg border p-4 transition-colors hover:bg-accent ${
                      selectedGroup?.id === group.id ? 'border-primary bg-accent' : 'border-border'
                    }`}
                    onClick={() => fetchGroupDetails(group.id)}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-semibold text-foreground">{group.name}</h3>
                        <p className="text-sm text-muted-foreground">
                          {group.member_count} {group.member_count === 1 ? 'member' : 'members'}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        {group.is_creator && (
                          <span className="rounded bg-primary/10 px-2 py-1 text-xs text-primary">
                            Creator
                          </span>
                        )}
                        <Shield className="h-4 w-4 text-accent" />
                      </div>
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>

          {/* Group Details */}
          <Card>
            <CardHeader>
              <CardTitle>Group Details</CardTitle>
              <CardDescription>
                {selectedGroup ? 'Manage group members' : 'Select a group to view details'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="flex items-center justify-center py-8">
                  <div className="text-sm text-muted-foreground">Loading...</div>
                </div>
              ) : selectedGroup ? (
                <div className="space-y-4">
                  {/* Group Info */}
                  <div className="rounded-lg border border-border bg-muted/50 p-4">
                    <h3 className="mb-2 font-semibold text-foreground">{selectedGroup.name}</h3>
                    <p className="text-sm text-muted-foreground">
                      {selectedGroup.members.length} {selectedGroup.members.length === 1 ? 'member' : 'members'}
                    </p>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex gap-2">
                    {selectedGroup.is_creator && (
                      <>
                        <Dialog open={addMemberDialogOpen} onOpenChange={setAddMemberDialogOpen}>
                          <DialogTrigger asChild>
                            <Button variant="outline" size="sm">
                              <UserPlus className="mr-2 h-4 w-4" />
                              Add Member
                            </Button>
                          </DialogTrigger>
                          <DialogContent>
                            <DialogHeader>
                              <DialogTitle>Add Member to {selectedGroup.name}</DialogTitle>
                              <DialogDescription>
                                Enter the email address of the user you want to add
                              </DialogDescription>
                            </DialogHeader>
                            <div className="space-y-4">
                              <div>
                                <Label htmlFor="member-email">Member Email</Label>
                                <Input
                                  id="member-email"
                                  type="email"
                                  placeholder="user@example.com"
                                  value={newMemberEmail}
                                  onChange={(e) => setNewMemberEmail(e.target.value)}
                                />
                              </div>
                            </div>
                            <DialogFooter>
                              <Button variant="outline" onClick={() => setAddMemberDialogOpen(false)}>
                                Cancel
                              </Button>
                              <Button onClick={handleAddMember} disabled={loading}>
                                {loading ? 'Adding...' : 'Add Member'}
                              </Button>
                            </DialogFooter>
                          </DialogContent>
                        </Dialog>

                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => window.location.href = `/compose?group=${selectedGroup.id}`}
                        >
                          <Mail className="mr-2 h-4 w-4" />
                          Send Message
                        </Button>

                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => handleDeleteGroup(selectedGroup.id)}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          Delete Group
                        </Button>
                      </>
                    )}

                    {!selectedGroup.is_creator && (
                      <>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => window.location.href = `/compose?group=${selectedGroup.id}`}
                        >
                          <Mail className="mr-2 h-4 w-4" />
                          Send Message
                        </Button>

                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleLeaveGroup(selectedGroup.id)}
                        >
                          <LogOut className="mr-2 h-4 w-4" />
                          Leave Group
                        </Button>
                      </>
                    )}
                  </div>

                  {/* Members List */}
                  <div className="space-y-2">
                    <h4 className="text-sm font-semibold text-foreground">Members</h4>
                    <div className="space-y-2">
                      {selectedGroup.members.map((member) => (
                        <div
                          key={member.user_id}
                          className="flex items-center justify-between rounded-lg border border-border p-3"
                        >
                          <div>
                            <p className="text-sm font-medium text-foreground">{member.name || member.email}</p>
                            <p className="text-xs text-muted-foreground">{member.email}</p>
                          </div>
                          {member.is_creator && (
                            <span className="rounded bg-primary/10 px-2 py-1 text-xs text-primary">
                              Creator
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Encryption Info */}
                  <div className="rounded-lg border border-accent/20 bg-accent/5 p-4">
                    <div className="flex items-start gap-2">
                      <Shield className="mt-0.5 h-4 w-4 text-accent" />
                      <div>
                        <h4 className="text-sm font-semibold text-foreground">Quantum-Secure Encryption</h4>
                        <p className="text-xs text-muted-foreground">
                          All group messages are encrypted with Level 2 (Kyber512 + AES-256-GCM)
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-center py-12">
                  <div className="text-center">
                    <Users className="mx-auto mb-2 h-12 w-12 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">Select a group to view details</p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default GroupThreads;