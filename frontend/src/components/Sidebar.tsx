import { Link, useLocation } from 'react-router-dom';
import { Home, Mail, Send, Users, Settings, Shield, PenSquare } from 'lucide-react';
import { cn } from '@/lib/utils'; 

const Sidebar = () => {
  const location = useLocation();

  const navItems = [
    { path: '/dashboard', icon: Home, label: 'Dashboard' },
    { path: '/inbox', icon: Mail, label: 'Inbox' },
    { path: '/sent', icon: Send, label: 'Sent' },
    { path: '/compose', icon: PenSquare, label: 'Compose' },
    { path: '/threads', icon: Users, label: 'Groups' },
    { path: '/settings', icon: Settings, label: 'Settings' },
  ];

  return (
    <div className="w-64 bg-card border-r h-full flex flex-col">
      <div className="p-6 border-b">
        <div className="flex items-center gap-2">
          <Shield className="w-8 h-8 text-primary" />
          <div>
            <h1 className="text-xl font-bold">QMail</h1>
            <p className="text-xs text-muted-foreground">Quantum Secure</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4">
        <ul className="space-y-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;

            return (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={cn(
                    'flex items-center gap-3 px-4 py-3 rounded-lg transition-colors',
                    isActive
                      ? 'bg-primary text-primary-foreground'
                      : 'hover:bg-accent'
                  )}
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-medium">{item.label}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="p-4 border-t">
        <div className="text-xs text-muted-foreground">
          <p>Post-Quantum Encryption</p>
          <p className="font-mono">Kyber512 • AES-256</p>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;