# PhishGuard — Explainable Phishing Indicator Checker

A lightweight email-text screening tool using transparent heuristic rules. It is a learning project, **not a production spam filter** and not a guarantee that an email is safe.

## Run
```bash
python phishguard.py --input sample_email.txt
```
Python 3.10+, standard library only. The program reports indicators and a score; it does not open links or contact external services.
