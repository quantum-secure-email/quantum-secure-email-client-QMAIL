import DashboardLayout from '@/components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Mail, Shield, Inbox, Send } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';

const Dashboard = () => {
  const { user } = useAuth();

  const stats = [
    {
      title: 'Total Emails',
      value: '0',
      description: 'Emails in your inbox',
      icon: Mail,
      color: 'text-primary',
    },
    {
      title: 'Sent',
      value: '0',
      description: 'Messages sent today',
      icon: Send,
      color: 'text-accent',
    },
    {
      title: 'Encrypted',
      value: '100%',
      description: 'Quantum protected',
      icon: Shield,
      color: 'text-primary',
    },
    {
      title: 'Unread',
      value: '0',
      description: 'New messages',
      icon: Inbox,
      color: 'text-accent',
    },
  ];

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Welcome to Qmail</h1>
          <p className="text-muted-foreground">
            Your quantum-secure email dashboard
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {stats.map((stat) => (
            <Card key={stat.title} className="transition-all hover:shadow-lg">
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
                <stat.icon className={`h-4 w-4 ${stat.color}`} />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stat.value}</div>
                <p className="text-xs text-muted-foreground">{stat.description}</p>
              </CardContent>
            </Card>
          ))}
        </div>

        <Card className="border-2 border-primary/20 bg-gradient-to-br from-primary/5 to-accent/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" />
              Quantum Security Status
            </CardTitle>
            <CardDescription>
              Your emails are protected with state-of-the-art encryption
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Encryption Level</span>
                <span className="font-medium text-foreground">Active</span>
              </div>
              <div className="h-2 rounded-full bg-secondary">
                <div className="h-full w-full rounded-full bg-gradient-to-r from-primary to-accent" />
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              <div className="rounded-lg border border-border bg-card p-3">
                <div className="text-sm font-medium text-foreground">Level 1</div>
                <div className="text-xs text-muted-foreground">Standard Gmail</div>
              </div>
              <div className="rounded-lg border border-border bg-card p-3">
                <div className="text-sm font-medium text-foreground">Level 2</div>
                <div className="text-xs text-muted-foreground">Post-Quantum (Kyber)</div>
              </div>
              <div className="rounded-lg border border-border bg-card p-3">
                <div className="text-sm font-medium text-foreground">Level 3</div>
                <div className="text-xs text-muted-foreground">QKD + OTP</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>Get started with Qmail</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-sm text-muted-foreground">
              • Click "Compose Email" in the sidebar to send your first quantum-secure message
            </p>
            <p className="text-sm text-muted-foreground">
              • Inbox feature coming soon - view and manage received emails
            </p>
            <p className="text-sm text-muted-foreground">
              • Group Threads will enable secure team communication
            </p>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
};

export default Dashboard;
