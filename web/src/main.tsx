import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { inject } from '@vercel/analytics'
// Font serviti dal nostro stesso sito invece che dalla CDN di Google: ogni
// caricamento pagina da fonts.googleapis.com manda l'IP del visitatore a
// Google, un'area grigia reale della privacy (caso concreto: tribunale di
// Monaco, 2022) che la nostra stessa pagina Privacy dichiara di non fare.
import '@fontsource/inter/400.css'
import '@fontsource/inter/500.css'
import '@fontsource/inter/600.css'
import '@fontsource/inter/700.css'
import '@fontsource/inter/800.css'
import '@fontsource/jetbrains-mono/400.css'
import '@fontsource/jetbrains-mono/500.css'
import '@fontsource/jetbrains-mono/600.css'
import '@fontsource/anton/400.css'
import './index.css'
import App from './App.tsx'
import { LanguageProvider } from './i18n/LanguageContext.js'
import { ThemeProvider } from './lib/ThemeContext.js'

inject()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <LanguageProvider>
        <App />
      </LanguageProvider>
    </ThemeProvider>
  </StrictMode>,
)