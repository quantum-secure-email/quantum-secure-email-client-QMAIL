import { NavLink } from 'react-router-dom';
import { Home, Send, Users, Settings, Shield } from 'lucide-react';
import { cn } from '@/lib/utils';

const navigation = [
  { name: 'Dashboard', to: '/dashboard', icon: Home },
  { name: 'Compose Email', to: '/compose', icon: Send },
  { name: 'Group Threads', to: '/threads', icon: Users },
  { name: 'Settings', to: '/settings', icon: Settings },
];

const Sidebar = () => {
  return (
    <div className="flex h-full w-64 flex-col border-r border-border bg-card">
      {/* Logo */}
      <div className="flex h-16 items-center gap-3 border-b border-border px-6">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-accent">
          <Shield className="h-5 w-5 text-primary-foreground" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-foreground">Qmail</h1>
          <p className="text-xs text-muted-foreground">Quantum Secure</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-4">
        {navigation.map((item) => (
          <NavLink
            key={item.name}
            to={item.to}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-lg px-4 py-3 text-sm font-medium transition-all duration-200',
                isActive
                  ? 'bg-primary text-primary-foreground shadow-sm'
                  : 'text-muted-foreground hover:bg-secondary hover:text-foreground'
              )
            }
          >
            <item.icon className="h-5 w-5" />
            {item.name}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="border-t border-border p-4">
        <div className="rounded-lg bg-gradient-to-br from-primary/10 to-accent/10 p-4">
          <div className="flex items-center gap-2 text-sm font-medium text-foreground">
            <Shield className="h-4 w-4 text-primary" />
            <span>Quantum Protected</span>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Your emails are secured with post-quantum encryption
          </p>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
