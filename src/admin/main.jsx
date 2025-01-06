  
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { AdminSocketProvider } from './contexts/AdminSocket';
import './index.css';

// Add base Tailwind styles
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <AdminSocketProvider>
      <App />
    </AdminSocketProvider>
  </React.StrictMode>
);