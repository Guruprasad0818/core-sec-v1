CBAD Stage 1 Git Hook Prototype

This folder contains a prototype implementation of CBAD client-side Git hooks.

Files:
- `cbad_feature_collector.py`: feature extraction engine for pre-commit and pre-push.
- `local_feature_store.py`: local `.git/cbad/features` store writer.
- `pre_commit.py`: hook script for `pre-commit`.
- `pre_push.py`: hook script for `pre-push`.

Install Python dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -U pip
```

Run the hooks manually:

```powershell
cd c:\Users\GURUPRASAD\OneDrive\Desktop\core-sec-v1
python stage1\pre_commit.py
```

To simulate a pre-push hook with stdin:

```powershell
"0000000000000000000000000000000000000000 3f3d3c3b2a1b0c9d8e7f6a5b4c3d2e1f0a0b0c0d refs/heads/main" | python stage1\pre_push.py
```

To install the hook wrappers:

```powershell
copy stage1\pre_commit.py .git\hooks\pre-commit
copy stage1\pre_push.py .git\hooks\pre-push
icacls .git\hooks\pre-commit /grant %USERNAME%:RX
icacls .git\hooks\pre-push /grant %USERNAME%:RX
```
