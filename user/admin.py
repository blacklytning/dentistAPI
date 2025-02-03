from django.contrib import admin
from . import models

# Register your models here.
admin.site.register(models.Allergy)
admin.site.register(models.Details)
admin.site.register(models.MedicalCondition)
admin.site.register(models.MedicalHistory)
admin.site.register(models.AllergyHistory)
