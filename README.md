# dentist-API

1. Create virtual environment

```sh
conda create -n dentist python=3.12
```

2. Activate virtual environment

```sh
conda activate dentist
```

3. Install requirements

```sh
pip install -r requirements.txt
```

4. Create database in postgres (via psql)

```sql
CREATE DATABASE dentist;
```

5. **Change .env.example to .env and add proper environment variables according to your setup**

6. Make migrations

```sh
python manage.py makemigrations
```

```sh
python manage.py makemigrations authentication
```

```sh
python manage.py makemigrations messaging
```

```sh
python manage.py makemigrations doctor
```

```sh
python manage.py makemigrations patient
```

7. Migrate

```sh
python manage.py migrate
```

```sh
python manage.py migrate django_celery_beat
```

8. Create superuser

```sh
python manage.py createsuperuser
```

(don't set email, set a simple username and password)

9. Populate tables

```sh
python manage.py populate_treatments
```

```sh
python manage.py populate_prescriptions
```

10. Create roles

```sh
python manage.py runserver
```

- Go to `http://localhost:8000/admin`
- Enter your superuser credentials from step 7
- In the `Authentication` app add a doctor and admin
- **STRICTLY** Keep password field empty for all the users

## For testing whatsapp functionality (OPTIONAL for keeping development server online)

1. Run Celery worker

```sh
celery -A dentistAPI worker --loglevel=info --pool=solo
```

2. Run Celery beat

```sh
celery -A dentistAPI beat --scheduler django_celery_beat.schedulers.DatabaseScheduler --loglevel=info
```

# dentist-UI

1. Clone the frontend (get out of this directory)

```sh
git clone https://github.com/tejashriiii/dentistFrontend
```

2. Follow instructions from [here](https://github.com/tejashriiii/dentistFrontend)
3. Set password for doctor and admin with the signup page
4. Login as the admin
5. Register the patient using registration form

## Production steps (FOR DEPLOYMENT ONLY)

- Replace`pyscopg2-binary` with the entire package built using the c libraries
- Follow django's article and setup `httpd` and all
