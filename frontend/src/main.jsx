// Application entry point.
// React renders the <App /> component into the <div id="root"> in index.html.
// BrowserRouter gives us real URLs (/alerts, /incidents, ...) without page reloads.
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.jsx'
import './styles/index.css'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
)
