import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';

const AuthComplete = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { login } = useAuth();

  useEffect(() => {
    const completeAuth = async () => {
      const token = searchParams.get('token');
      
      if (!token) {
        navigate('/?error=no_token');
        return;
      }

      // Store token as cookie
      document.cookie = `session_token=${token}; path=/; max-age=604800; SameSite=Lax`;
      
      // Get user info
      const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
      const response = await fetch(`${apiUrl}/auth/me`, {
        credentials: 'include',
      });

      if (response.ok) {
        const userData = await response.json();
        login(userData);
        navigate('/dashboard');
      } else {
        navigate('/?error=auth_failed');
      }
    };

    completeAuth();
  }, [searchParams, navigate, login]);

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="text-center">
        <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
        <p className="mt-4 text-lg">Completing authentication...</p>
      </div>
    </div>
  );
};

export default AuthComplete;