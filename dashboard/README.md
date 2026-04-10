# Claude Squad — Usage Dashboard

Web-based dashboard that monitors usage and rate limits across multiple Claude accounts in a single view.

## Quick Start

```bash
python3 dashboard/server.py
# Opens http://localhost:8420
```

The server auto-discovers accounts on startup and begins background polling.

## What It Does

Monitors 8+ accounts simultaneously instead of checking each one manually at https://claude.ai/settings/usage:

- **Anthropic OAuth accounts**: Polls the undocumented `/api/oauth/usage` endpoint every 10 minutes
- **Z.AI / MiniMax accounts**: Probes the messages API with `max_tokens: 1` to capture rate-limit headers every 15 minutes
- **Manual accounts**: Added via the dashboard UI

## Architecture

```
dashboard/
  server.py       -- HTTP server (http.server) + API endpoints
  accounts.py     -- Account discovery from csq credential store
  poller.py       -- Background polling with rate-limit respect
  cache.py        -- In-memory cache with TTL
  static/
    index.html    -- Dashboard UI
    dashboard.js  -- Frontend logic (vanilla JS)
    style.css     -- Dark theme styling
  tests/
    test_cache.py
    test_accounts.py
    test_poller.py
    test_server.py
```

## API Endpoints

| Method | Path                      | Description                          |
| ------ | ------------------------- | ------------------------------------ |
| GET    | `/`                       | Dashboard UI                         |
| GET    | `/api/accounts`           | All accounts with current usage      |
| GET    | `/api/account/{id}/usage` | Detailed usage for one account       |
| GET    | `/api/refresh`            | Force refresh (respects rate limits) |
| POST   | `/api/accounts`           | Add a manual account                 |

## Account Discovery

Accounts are auto-discovered from:

1. `~/.claude/accounts/credentials/*.json` — Anthropic OAuth tokens
2. `~/.claude/settings-zai.json` — Z.AI provider
3. `~/.claude/settings-mm.json` — MiniMax provider
4. `~/.claude/accounts/dashboard-accounts.json` — Manual accounts

## Options

```bash
python3 dashboard/server.py --port 9000        # Custom port
python3 dashboard/server.py --no-poll           # Disable background polling
python3 dashboard/server.py --host 0.0.0.0      # Bind to all interfaces (not recommended)
```

## Running Tests

```bash
python3 dashboard/tests/test_cache.py
python3 dashboard/tests/test_accounts.py
python3 dashboard/tests/test_poller.py
python3 dashboard/tests/test_server.py
```

## Security

- Binds to `127.0.0.1` only (local access)
- Never logs full tokens (prefix only)
- Tokens stay in memory, never written to new files
- Reads credential files read-only
- Python 3 stdlib only (no PyPI dependencies)
