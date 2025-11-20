import { createContext, useContext, useState, useEffect, ReactNode } from 'react';

interface User {
  id: number;
  name: string;
  email: string;
  picture?: string;
}

interface AuthContextType {
  user: User | null;
  login: (userData: User) => void;
  logout: () => void;
  isAuthenticated: boolean;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

// Helper to get token from cookie
const getTokenFromCookie = (): string | null => {
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === 'session_token') {
      return value;
    }
  }
  return null;
};

export const AuthProvider = ({ children }: AuthProviderProps) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

  useEffect(() => {
    // Check authentication status from backend
    const checkAuth = async () => {
      try {
        const token = getTokenFromCookie();
        
        if (!token) {
          console.log('No session token found');
          setUser(null);
          setLoading(false);
          return;
        }

        console.log('Found session token, checking with backend...');

        // CRITICAL: Send token in Authorization header for cross-origin requests
        const response = await fetch(`${apiUrl}/auth/me`, {
          credentials: 'include',
          headers: {
            'Authorization': `Bearer ${token}`, // Send token in header
          },
        });

        if (response.ok) {
          const userData = await response.json();
          console.log('User authenticated:', userData.email);
          setUser(userData);
        } else {
          console.error('Auth check failed:', response.status);
          setUser(null);
          // Clear invalid cookie
          document.cookie = 'session_token=; path=/; max-age=0';
        }
      } catch (error) {
        console.error('Auth check failed:', error);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
  }, [apiUrl]);

  const login = (userData: User) => {
    setUser(userData);
  };

  const logout = async () => {
    try {
      const token = getTokenFromCookie();
      
      await fetch(`${apiUrl}/auth/logout`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
    } catch (error) {
      console.error('Logout failed:', error);
    }
    
    // Clear cookie
    document.cookie = 'session_token=; path=/; max-age=0';
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        logout,
        isAuthenticated: !!user,
        loading,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
