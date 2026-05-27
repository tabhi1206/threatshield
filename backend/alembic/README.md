Alembic migration scaffolding for ThreatShield backend.

Usage examples:

1. Install alembic (in your virtualenv):
   pip install alembic

2. Initialize (if you want to re-init locally):
   alembic init backend/alembic

3. Generate a migration (autogenerate):
   DATABASE_URL="postgres://user:pass@host:5432/db" alembic -c backend/alembic.ini revision --autogenerate -m "create tables"

4. Apply migrations:
   DATABASE_URL="postgres://..." alembic -c backend/alembic.ini upgrade head

Notes:
- The `env.py` reads `DATABASE_URL` from the environment if present.
- For production, use a managed Postgres and run migrations as part of your CI/CD.
