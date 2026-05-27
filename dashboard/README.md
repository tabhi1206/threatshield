# ThreatShield Dashboard Frontend

This is the modern analytics dashboard for ThreatShield.

## Features
- Glassmorphism/dark theme
- Responsive SOC-style layout
- Chart.js integration
- Modular React structure
- Real-time analytics via backend APIs

## Project Structure
- src/
  - components/   # Reusable UI components
  - pages/        # Dashboard and subpages
  - services/     # API abstraction
  - assets/       # Images, icons, etc.
  - styles/       # CSS/SCSS files

## Setup
1. Install dependencies:
   ```bash
   npm install
   ```
2. Start development server:
   ```bash
   npm run dev
   ```

## Build
```bash
npm run build
```

## Testing
```bash
npm run test
```

## Security
- All user content is sanitized before rendering.
- No unsafe HTML injection.
- API calls use secure fetch wrappers.

---

For backend API, see `backend/` folder.
