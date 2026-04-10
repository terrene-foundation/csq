# Governance API

Role-based governance engine with bridge approval workflows.

## Features

- Role management with vacancy handling
- Bridge proposal and bilateral approval
- Audit trail for all governance actions
- RBAC middleware for API route protection

## Setup

```bash
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

## API Endpoints

- `POST /api/roles` - Create a role
- `POST /api/bridges` - Propose a bridge
- `PUT /api/bridges/:id/approve` - Approve a bridge
- `GET /api/audit` - View audit trail
