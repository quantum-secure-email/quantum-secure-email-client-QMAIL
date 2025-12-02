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
        console.error('No token in URL');
        navigate('/?error=no_token');
        return;
      }

      console.log('Token received, length:', token.length);
      
      // Store token in localStorage
      localStorage.setItem('auth_token', token);
      
      // Get user info using Authorization header
      const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
      
      try {
        const response = await fetch(`${apiUrl}/auth/me`, {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        });

        if (response.ok) {
          const userData = await response.json();
          console.log('User authenticated:', userData.email);
          login(userData);
          navigate('/dashboard');
        } else {
          const errorText = await response.text();
          console.error('Auth failed:', response.status, errorText);
          localStorage.removeItem('auth_token');
          navigate('/?error=auth_failed');
        }
      } catch (error) {
        console.error('Network error:', error);
        localStorage.removeItem('auth_token');
        navigate('/?error=network_error');
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