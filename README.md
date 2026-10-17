# Mazda6 AI Assistant

[![Checks](https://github.com/ArsPoghosyan/Mazda6-AI-Assistant/actions/workflows/ci.yml/badge.svg)](https://github.com/ArsPoghosyan/Mazda6-AI-Assistant/actions/workflows/ci.yml)

An independent, unofficial Mazda6 information assistant in early development.
Unaffiliated with Mazda.

**Status: early development.** This repository currently contains the local
application foundation. The full assistant is planned and is not available yet.

## Engineering workflow

This is a personal project with publicly available code, tests, and development
history. External contributions are not being accepted.

Development proceeds in small, testable changes. GitHub Actions is configured for
backend tests/lint/types and frontend lint/build. Results are available in the
[Actions tab](https://github.com/ArsPoghosyan/Mazda6-AI-Assistant/actions).

## Working now

- React/TypeScript/Vite/Tailwind development page with live API connectivity status.
- FastAPI `GET /api/v1/health` with a typed JSON contract.
- Backend contract test, Python lint/type checks, frontend lint/type/build checks.

Chat, authentication, persistence, vehicle selection, retrieval, and AI calls are
not implemented. No API keys, database, Docker, or cloud account are required for
this first slice. Embeddings are planned with OpenAI `text-embedding-3-small`
(1536 dimensions); answer generation is planned with Groq.

## Windows local setup

Prerequisites: Python 3.12, uv, and Node.js 24 LTS with npm. Verify `py -3.12
--version`, `uv --version`, `node --version`, and `npm --version` in a new PowerShell
window. A listed Python installation may still have an invalid launcher/path;
select a working interpreter in PyCharm rather than editing an existing venv.

On the original development machine, portable Node 24.22.0 and uv 0.13.1 were
installed under the ignored `.tools` directory to verify this slice. If those
directories are present, run this from the repository root in **each terminal**
before following the commands below (this changes only that terminal's PATH):

```powershell
$taskRoot = (Get-Location).Path
$env:Path = (Join-Path $taskRoot '.tools/node-v24.22.0-win-x64') + ';' + (Join-Path $taskRoot '.tools/bootstrap/Scripts') + ';' + $env:Path
```

These local tools are not included in Git; a fresh clone needs the prerequisites
installed separately. The Node archive was verified against its official SHA-256
checksum. The existing root virtual environment was preserved.

From the repository root, install the locked backend dependencies:

```powershell
Set-Location backend
uv sync --locked
uv run uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In a second PowerShell terminal, from the repository root:

```powershell
Set-Location frontend
npm ci
npm run dev
```

Open http://127.0.0.1:5173. It should report **API connected**. Stop the backend
and use **Try again** after reloading to see the unavailable state. API docs are
at http://127.0.0.1:8000/docs. The health response checks process liveness only.

Vite forwards `/api` to `127.0.0.1:8000`; no broad CORS permission is needed.
Both servers bind to loopback. The production build does not supply an API server;
same-origin production hosting will be configured in a later deployment task.

For PyCharm, use `backend/.venv/Scripts/python.exe` after `uv sync`, with `backend`
as the working directory. The pre-existing root `.venv` is not used by this setup.

The current slice requires no `.env`. Keep future credentials in ignored backend
environment files, never in frontend `VITE_*` variables. `.env.example` contains
guidance only, with no secrets.

## Checks

From `backend`:

```powershell
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

From `frontend`:

```powershell
npm run lint
npm run build
```

`build` includes the strict TypeScript check. Tests require no live APIs.
Dependency versions are recorded in `backend/uv.lock` and `frontend/package-lock.json`.
GitHub Actions runs these checks without provider secrets.

The next focused task is PostgreSQL/pgvector setup, database migrations, and a
database readiness check.

## License

Project code is available under the [MIT License](LICENSE).
Third-party dependencies and automotive source material retain their own licenses.
No Mazda manufacturer manuals or proprietary diagrams are included in this repository.
