# ICDRS: Intelligent Cybercrime Detection and Reporting System

ICDRS is a Django academic prototype demonstrating lightweight network-traffic classification, internal incident creation, and public cybercrime reporting. It uses SQLite for local persistence and a small scikit-learn Random Forest model.

## Features

- Public landing page, manual incident submission, and confirmation with a reference number
- Detection lab with built-in scenarios and validated numeric input
- Local Random Forest predictions, with a clearly labelled simulation fallback
- Automatic internal incidents for suspicious detections
- Staff-only management dashboard, review queue, incident status updates, and CSV export
- Local detection history and model status

## Requirements and setup

The project was verified with Python 3.12.10, Django 6.1.2, scikit-learn 1.9.0, joblib 1.5.3, and NumPy 2.5.4. From the project folder in Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install django scikit-learn joblib numpy
python manage.py migrate
python manage.py train_demo_model
python manage.py create_admin --username admin
python manage.py runserver 127.0.0.1:8000
```

The account-creation command prompts for a password twice without echoing it. To change an existing account's password:

```powershell
python manage.py changepassword admin
```

Open http://127.0.0.1:8000/ after the server starts.

## Current local account

The existing local SQLite database was inspected during stabilization. It has an active staff account named `admin`; the previously documented demo password is still valid. This is a weak demonstration-only credential: change it using `python manage.py changepassword admin` before any demonstration on a network or before sharing the database. Do not reuse it elsewhere.

For a new database, create a staff account with the interactive `python manage.py create_admin --username admin` command. If the username already exists, that command does not change its password; use `changepassword`.

## Machine-learning model

The model is trained from `data/demo_network_data.csv`, a small illustrative dataset containing 17 labelled examples. It is not NSL-KDD, CICIDS2017, PhishTank, or representative real-world traffic. `python manage.py train_demo_model` saves:

- `ml_models/demo_model.joblib`
- `ml_models/demo_model_metadata.json`

The reported accuracy, precision, recall, and F1 score are computed from a held-out split of this very small and artificial dataset (five test rows). They are not reliable estimates of real-world cybercrime detection performance. Model score is not a probability that a crime occurred. No scaler is used because the Random Forest model does not require feature scaling.

When artifacts are missing or invalid, the app uses explicitly labelled Simulation Mode. A failure to load or validate existing model artifacts is included in the persisted detection explanation.

## Configuration and security notes

- `DJANGO_DEBUG` defaults to `true` for local development. Set `DJANGO_DEBUG=false` outside local development.
- `DJANGO_SECRET_KEY` is required when `DJANGO_DEBUG=false`. In local development, a temporary random key is generated when none is set; sessions may need a new login after restarting the server.
- `DJANGO_ALLOWED_HOSTS` is a comma-separated host list. Its local default is `localhost,127.0.0.1,[::1]`.
- Evidence uploads are limited to 5 MB and to PDF, PNG, JPG/JPEG, TXT, or CSV filename extensions. Downloads require staff authentication and are served as attachments. Uploaded evidence is not executed. Extension checks do not prove file contents are safe; do not upload sensitive or untrusted evidence to a public deployment.
- Tailwind CSS is loaded from its CDN, so the interface requires internet access to receive the styling.
- This is an academic local prototype: it does not capture live network packets or transmit reports to external authorities.

## Tests and checks

Run the automated tests and Django checks with:

```powershell
python manage.py test
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py migrate --check
```

## Main project structure

- `core/` — Django models, views, forms, detection logic, management commands, and tests
- `data/demo_network_data.csv` — illustrative training examples
- `ml_models/` — local model and evaluation metadata
- `templates/` — shared and page-specific Django templates
- `icdrs/` — Django settings and project URLs
- `db.sqlite3` — local incident and detection database
