# ChainTrace: Blockchain-Based Cyber Forensic Chain of Custody

Flask + SQLite + a custom SHA-256 blockchain.

## Run locally (Windows)
```
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Demo accounts (password = username + 123)
admin / ravi / kumar / priya / judge

## Features
- Evidence upload with SHA-256 fingerprint
- Every handover sealed as a block (hash-linked)
- File hash re-checked before each transfer
- Blockchain explorer with tamper highlighting
- Tamper Lab (admin) to demo attacks and detection
- JSON API at /api/chain

## Deploy for a public link (Render.com)
1. Push this folder to a GitHub repository.
2. Render.com > New > Web Service > connect the repo.
3. Build: `pip install -r requirements.txt`   Start: `gunicorn app:app`
4. Add env var SECRET_KEY = any long random text. Deploy.
Note: on the free plan the disk is temporary, so data resets when the service restarts. Fine for demos.
