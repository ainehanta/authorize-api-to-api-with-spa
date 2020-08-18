import React, { useState, useEffect, useCallback } from 'react';
import { useAuth0 } from '@auth0/auth0-react';

function App() {
  const { loginWithRedirect, logout, user, isAuthenticated, getAccessTokenSilently } = useAuth0();

  const [hermesTokenResponse, setHermesTokenResponse] = useState({});

  const fetchHermesToken = useCallback(async () => {
    const options = { mode: 'cors' };

    if (isAuthenticated) {
      const token = await getAccessTokenSilently();
      const headers = { 'Authorization': `Bearer ${token}` };
      options.headers = headers;
    }
    
    const response = await fetch('http://localhost:5000', options);
    const body = await response.json();
    setHermesTokenResponse(body);
  }, [getAccessTokenSilently, isAuthenticated]);

  useEffect(() => {
    fetchHermesToken();
  }, [isAuthenticated, fetchHermesToken]);

  return (
    <div>
      <p>
        {isAuthenticated ? <button onClick={logout}>Logout</button> : <button onClick={loginWithRedirect}>Login</button>}
      </p>
      <pre>{JSON.stringify(user, null, 2)}</pre>
      <p><a href="http://localhost:5000/authorize" target="_blank" rel="noopener noreferrer">Authorize Hermes</a></p>
      <p>clientと異なるアカウントでhermesにログインした場合、一旦clientをログアウトすると再紐付けできるようになります。</p>
      <pre>{JSON.stringify(hermesTokenResponse, null, 2)}</pre>
      <button onClick={fetchHermesToken}>Reload Hermes Token</button>
    </div>
  );
}

export default App;
