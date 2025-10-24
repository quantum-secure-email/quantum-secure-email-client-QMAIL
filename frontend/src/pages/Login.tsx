import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import GoogleSignIn from '@/components/GoogleSignIn';
import { Shield, Lock, Zap } from 'lucide-react';

const Login = () => {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard');
    }
  }, [isAuthenticated, navigate]);

  return (
    <div className="flex min-h-screen w-full items-center justify-center bg-gradient-to-br from-background via-background to-secondary">
      <div className="w-full max-w-6xl px-4">
        <div className="grid gap-8 lg:grid-cols-2 lg:gap-12">
          {/* Left side - Hero content */}
          <div className="flex flex-col justify-center space-y-6">
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-primary to-accent shadow-lg">
                  <Shield className="h-8 w-8 text-primary-foreground" />
                </div>
                <div>
                  <h1 className="text-4xl font-bold text-foreground">Qmail</h1>
                  <p className="text-lg text-muted-foreground">Quantum Secure Email</p>
                </div>
              </div>

              <p className="text-xl text-foreground">
                Experience the future of secure communication with quantum-resistant encryption
              </p>
            </div>

            <div className="space-y-4">
              <div className="flex items-start gap-4 rounded-lg border border-border bg-card p-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                  <Lock className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-semibold text-foreground">Post-Quantum Encryption</h3>
                  <p className="text-sm text-muted-foreground">
                    Protected against future quantum computer attacks
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-4 rounded-lg border border-border bg-card p-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/10">
                  <Zap className="h-5 w-5 text-accent" />
                </div>
                <div>
                  <h3 className="font-semibold text-foreground">Multi-Level Security</h3>
                  <p className="text-sm text-muted-foreground">
                    Choose your encryption level for every message
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-4 rounded-lg border border-border bg-card p-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                  <Shield className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-semibold text-foreground">QKD Integration</h3>
                  <p className="text-sm text-muted-foreground">
                    Quantum Key Distribution for ultimate security
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Right side - Sign in card */}
          <div className="flex items-center justify-center">
            <div className="w-full max-w-md space-y-8 rounded-2xl border border-border bg-card p-8 shadow-2xl">
              <div className="space-y-2 text-center">
                <h2 className="text-3xl font-bold text-foreground">Welcome to Qmail</h2>
                <p className="text-muted-foreground">
                  Sign in to access your quantum-secure mailbox
                </p>
              </div>

              <div className="space-y-4">
                <GoogleSignIn />

                <div className="rounded-lg border border-border bg-muted/50 p-4">
                  <p className="text-xs text-muted-foreground">
                    <strong>Note:</strong> To enable Google Sign-In, you need to configure your
                    Google OAuth client ID. Visit the Google Cloud Console to set up your OAuth 2.0
                    credentials and replace the client ID in GoogleSignIn.tsx.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
