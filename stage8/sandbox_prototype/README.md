Sandbox prototype

This folder contains a minimal sandbox prototype for Stage 8 ephemeral environments.

Files:
- `data_seeder.py`: creates a demo SQLite DB and inserts a canary user.
- `report_uploader.py`: reads a ZAP JSON report, computes a toy risk score, and prints a ticket payload when threshold is exceeded.
- `sandbox-cr.yaml`: example Sandbox CRD manifest.

Quickstart:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python data_seeder.py
# create a minimal fake zap-report.json for testing
python -c "import json; print(json.dumps({'site':[{'alerts':[{'risk':'High'}]}]}, indent=2))" > zap-report.json
python report_uploader.py zap-report.json 0.5
```
