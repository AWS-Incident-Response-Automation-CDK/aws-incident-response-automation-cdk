import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import { AuthProvider } from "react-oidc-context";
import { useState, useEffect } from 'react'

const Root = () => {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/config.json')
      .then(res => res.json())
      .then(data => {
        setConfig(data);
        setLoading(false);
      })
      .catch(err => {
        console.error("Failed to load config", err);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div style={{display: 'flex', justifyContent: 'center', marginTop: '50px'}}>Loading configuration...</div>;
  }

  if (!config) {
    return <div>Error loading configuration. Please check console.</div>;
  }

  const onSigninCallback = (_user) => {
    window.history.replaceState({}, document.title, window.location.pathname);
  };

  const cognitoAuthConfig = {
    authority: `https://cognito-idp.${config.region}.amazonaws.com/${config.cognito.userPoolId}`,
    client_id: config.cognito.clientId,
    redirect_uri: window.location.origin,
    response_type: "code",
    scope: "email openid profile",
    onSigninCallback: onSigninCallback,
  };

  return (
      <AuthProvider {...cognitoAuthConfig}>
        <App config={config} /> 
      </AuthProvider>
    );
};

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <Root />
  </StrictMode>,
)
