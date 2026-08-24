import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

// Las fuentes se empaquetan con la aplicacion en lugar de pedirlas a un CDN:
// SecScan promete que no se comunica con ningun servidor, y eso incluye
// tambien las peticiones de una tipografia.
import '@fontsource/sora/latin-600.css';
import '@fontsource/sora/latin-700.css';
import '@fontsource/ibm-plex-sans/latin-400.css';
import '@fontsource/ibm-plex-sans/latin-500.css';
import '@fontsource/ibm-plex-sans/latin-600.css';
import '@fontsource/ibm-plex-mono/latin-400.css';
import '@fontsource/ibm-plex-mono/latin-500.css';

import App from './App';
import './styles/global.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
