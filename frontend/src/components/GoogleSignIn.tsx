import { useEffect } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

declare global {
  interface Window {
    google: any;
  }
}

interface GoogleSignInProps {
  onSuccess?: () => void;
}

// Full Gmail scope (use the one you configured)
const GMAIL_SCOPES = "https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.send";

const GoogleSignIn = ({ onSuccess }: GoogleSignInProps) => {
  const { login } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    document.body.appendChild(script);

    script.onload = () => {
      if (!window.google) {
        console.error("GIS library not loaded");
        return;
      }

      // initialize ID token flow
      try {
        window.google.accounts.id.initialize({
          client_id: import.meta.env.VITE_GOOGLE_CLIENT_ID,
          callback: handleCredentialResponse,
          ux_mode: "popup",
          auto_select: false,
        });

        window.google.accounts.id.renderButton(
          document.getElementById("google-signin-button"),
          { theme: "outline", size: "large", width: 280, text: "signin_with" }
        );

        // one-time console statement
        console.info("[GIS] id.initialize and renderButton completed");
      } catch (e) {
        console.error("GIS initialize failed:", e);
      }
    };

    return () => {
      try {
        document.body.removeChild(script);
      } catch {}
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Creates a token client on-demand (inside the user gesture) and requests access token
  const createAndRequestToken = (loginHint?: string) => {
    if (!window.google || !window.google.accounts || !window.google.accounts.oauth2) {
      console.error("google.accounts.oauth2 not available to init token client");
      toast.error("Internal error: OAuth client not ready");
      return;
    }

    const tc = window.google.accounts.oauth2.initTokenClient({
      client_id: import.meta.env.VITE_GOOGLE_CLIENT_ID,
      scope: GMAIL_SCOPES,
      // The callback receives the token response when successful (or an error)
      callback: (resp: any) => {
        if (resp.error) {
          console.error("[token-client] error:", resp);
          toast.error("Failed to obtain Gmail token");
          return;
        }
        // Store access token for backend calls
        console.info("[token-client] access_token received, expires_in:", resp.expires_in);
        sessionStorage.setItem("gmail_access_token", resp.access_token);
        sessionStorage.setItem("gmail_token_expires_in", String(resp.expires_in || 0));
        toast.success("Gmail permission granted");
      },
    });

    // Request the token immediately — must be called inside a user gesture.
    try {
      // If loginHint provided use it
      const opts: any = { prompt: "consent" }; // force consent
      if (loginHint) opts.login_hint = loginHint;
      tc.requestAccessToken(opts);
      console.info("[token-client] requestAccessToken called (prompt: consent)");
    } catch (e) {
      console.error("[token-client] requestAccessToken threw:", e);
      toast.error("Could not request Gmail token");
    }
  };

  // Called when Google returns an ID token (after user clicked the rendered button)
  const handleCredentialResponse = (response: any) => {
    try {
      console.info("[GIS] Got credential response");
      const token = response.credential;
      if (!token) {
        throw new Error("No ID token returned");
      }

      // parse ID token payload safely
      const base64Url = token.split(".")[1];
      const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split("")
          .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join("")
      );
      const userData = JSON.parse(jsonPayload);

      // Save auth in context
      login({
        name: userData.name,
        email: userData.email,
        picture: userData.picture,
        token: token,
      });

      toast.success("Signed in (ID token). Now requesting Gmail permission...");

      // Immediately create token client and request access token while inside this user gesture.
      // Pass login_hint so Google reuses the same account if needed.
      createAndRequestToken(userData.email);

      if (onSuccess) onSuccess();
      else navigate("/dashboard");
    } catch (error) {
      console.error("Error handling credential response:", error);
      toast.error("Sign-in failed");
    }
  };

  return (
    <div className="flex flex-col items-center gap-4">
      <div id="google-signin-button" />
      <p className="text-sm text-muted-foreground">Sign in with your Google account to access Qmail</p>
      <small className="text-xs text-muted-foreground mt-2">
        You will be prompted to grant Gmail permissions when you sign in (if required).
      </small>
    </div>
  );
};

export default GoogleSignIn;
