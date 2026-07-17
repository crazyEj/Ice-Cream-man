# Ice Cream Platform

Secure, multi-channel backend architecture for an ice cream business spanning:

- **Physical Retail / POS** — Liquid Nitrogen Ice Cream Lab
- **B2B Wholesale Portal** — gyms/cafes ordering high-protein pints
- **Corporate Catering** — mobile catering booking & staff scheduling
- **D2C Subscriptions** — recurring gourmet pint delivery

## Repo Structure

icecream-platform/
├── architecture/
│   └── ARCHITECTURE.md        # Three-tier system design, ASCII diagram, channel mapping
├── database/
│   └── schema.sql              # PostgreSQL DDL: RBAC, POS, wholesale, catering, subscriptions, audit log
├── services/
│   └── auth-service/
│       ├── auth_service.py     # FastAPI OIDC + MFA (TOTP) + JWT + RBAC boilerplate
│       ├── requirements.txt
│       └── .env.example
├── docs/
│   └── SECURITY_CHECKLIST.md   # Cloud deployment security checklist (AWS/GCP)
└── .github/workflows/
    └── ci.yml                  # Lint + dependency audit on push/PR


## Design Principles

- **Zero raw cardholder data** — all payments go through Stripe tokenization (PCI-DSS SAQ A / A-EP scope only).
- **RBAC everywhere** — enforced at the API Gateway, per-service middleware, and PostgreSQL Row-Level Security.
- **OAuth2/OIDC + mandatory MFA** for staff, admin, and wholesale-portal roles.
- **Isolated data tier** — PostgreSQL has no public route; only the app subnet can reach port 5432.
- **Append-only audit log** — administrative actions are immutable at the DB grant level.

See [`architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md) for the full diagram and rationale, and
[`docs/SECURITY_CHECKLIST.md`](docs/SECURITY_CHECKLIST.md) before deploying to production.

## Local Setup (auth-service)

```bash
cd services/auth-service
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in real values, .env is gitignored
uvicorn auth_service:app --reload
```

## Database

```bash
createdb icecream_platform
psql icecream_platform -f database/schema.sql
```

## Status

This repository currently contains architecture, schema, and auth boilerplate. Data-access functions in
`auth_service.py` are stubbed (`NotImplementedError`) pending wiring to a real Postgres connection pool —
see open issues.

## License

See [LICENSE](LICENSE). If this is a proprietary/commercial product, replace the MIT license with a private
repo or a proprietary license before pushing real business logic — MIT is included here only as a placeholder.
