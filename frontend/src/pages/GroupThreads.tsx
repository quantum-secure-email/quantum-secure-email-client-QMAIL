import DashboardLayout from '@/components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Users, MessageSquare, Shield, Clock } from 'lucide-react';

const GroupThreads = () => {
  return (
    <DashboardLayout>
      <div className="mx-auto max-w-4xl space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Group Threads</h1>
          <p className="text-muted-foreground">
            Secure team communication coming soon
          </p>
        </div>

        <Card className="border-2 border-dashed border-border">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5 text-primary" />
              Group Threads Feature
            </CardTitle>
            <CardDescription>This feature is currently under development</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="rounded-lg border border-border bg-gradient-to-br from-primary/5 to-accent/5 p-6 text-center">
              <Clock className="mx-auto mb-4 h-12 w-12 text-muted-foreground" />
              <h3 className="mb-2 text-xl font-semibold text-foreground">Coming Soon</h3>
              <p className="text-sm text-muted-foreground">
                We're working on bringing you secure group communication features
              </p>
            </div>

            <div className="space-y-4">
              <h3 className="font-semibold text-foreground">Planned Features:</h3>

              <div className="space-y-3">
                <div className="flex items-start gap-3 rounded-lg border border-border bg-card p-4">
                  <MessageSquare className="mt-0.5 h-5 w-5 text-primary" />
                  <div>
                    <h4 className="font-medium text-foreground">Group Conversations</h4>
                    <p className="text-sm text-muted-foreground">
                      Create encrypted group chats with multiple participants
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3 rounded-lg border border-border bg-card p-4">
                  <Shield className="mt-0.5 h-5 w-5 text-accent" />
                  <div>
                    <h4 className="font-medium text-foreground">End-to-End Encryption</h4>
                    <p className="text-sm text-muted-foreground">
                      All group messages protected with quantum-resistant encryption
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3 rounded-lg border border-border bg-card p-4">
                  <Users className="mt-0.5 h-5 w-5 text-primary" />
                  <div>
                    <h4 className="font-medium text-foreground">Team Management</h4>
                    <p className="text-sm text-muted-foreground">
                      Add or remove team members, assign roles, and manage permissions
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-lg bg-muted/50 p-4">
              <p className="text-sm text-muted-foreground">
                Want to be notified when this feature launches? Check back soon or contact us for
                updates on the development progress.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default GroupThreads;
