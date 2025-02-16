# celery.py

import os
from celery import Celery

# Set default Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dentistAPI.settings')

app = Celery('dentistAPI')

# Load task modules from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks in installed apps
app.autodiscover_tasks()

@app.task(bind=True,ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')

