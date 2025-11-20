import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Compose from "./pages/Compose";
import GroupThreads from "./pages/GroupThreads";
import SettingsPage from "./pages/SettingsPage";
import NotFound from "./pages/NotFound";
import Inbox from "./pages/Inbox";
import AuthComplete from './pages/AuthComplete';

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <AuthProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Login />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/inbox" element={<Inbox />} />  {/* ADD THIS */}
            <Route path="/compose" element={<Compose />} />
            <Route path="/threads" element={<GroupThreads />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/auth/complete" element={<AuthComplete />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </AuthProvider>
  </QueryClientProvider>
);

export default App;
