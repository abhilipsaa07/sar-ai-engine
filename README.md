# SAR AI Engine

AI-Powered Suspicious Activity Report Generator with RAG & Audit Trail.

## Stack
- **Frontend** — Vanilla HTML/CSS/JS, deployed on GitHub Pages
- **Backend** — FastAPI + SQLite
- **AI** — Anthropic Claude (claude-sonnet-4-6)
- **RAG** — FinCEN regulatory knowledge base with keyword retrieval

## Run locally

```bash
cd backend
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-...
uvicorn main:app --reload
```

Open `frontend/index.html` in your browser.

## Deploy backend (Render / Railway)

1. Push `backend/` to a new repo or subdirectory
2. Set env var `ANTHROPIC_API_KEY`
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard` | Stats summary |
| GET/POST | `/api/customers` | List / create customers |
| DELETE | `/api/customers/{id}` | Remove customer |
| GET/POST | `/api/transactions` | List / create transactions |
| POST | `/api/generate-sar` | Generate SAR narrative via Claude |
| GET | `/api/sar-reports` | List all SARs |
| GET | `/api/sar-reports/{id}` | Get single SAR |
| PATCH | `/api/sar-reports/{id}/status` | Update SAR status |
