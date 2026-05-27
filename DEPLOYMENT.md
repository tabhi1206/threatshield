ThreatShield — Local Docker & Render deployment notes

Local testing with Docker Compose

1. Copy `backend/.env.example` to `backend/.env` and update values (especially `DATABASE_URL` and `JWT_SECRET_KEY`).

2. Start services locally (requires Docker & docker-compose):

```bash
docker compose up --build
```

- Backend will be available at: `http://localhost:8000`
- Dashboard will be available at: `http://localhost:8080`

Using Render

1. Push your repository to GitHub and update `render.yaml` with the correct `repo` path.
2. In Render dashboard, create the `threatshield-backend` service using `backend/Dockerfile` (or let Render build from `render.yaml`).
3. Create a managed Postgres instance and set `DATABASE_URL` in service env vars.
4. Set `JWT_SECRET_KEY` and any other secrets in Render service environment settings.
5. For the dashboard, create a Static Site or Web Service pointing to `dashboard/`, set `VITE_API_BASE_URL` to `https://<your-backend>/api/v1`.

CI / Registry

- The included GitHub Actions `publish_images.yml` builds Docker images and pushes to GHCR. Ensure `GITHUB_TOKEN` has `packages: write` permission or configure a PAT with package write access.
