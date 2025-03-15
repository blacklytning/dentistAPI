from . import models
from patient import services as patient_services
from django.db import IntegrityError
from rest_framework import status


def delete_treatment_by_id(treatment_id):
    name = ""
    try:
        treatment_to_delete = models.Treatment.objects.get(id=treatment_id)
        name = treatment_to_delete.name
        treatment_to_delete.delete()
    except models.Treatment.DoesNotExist:
        return None, "This treatment does not exist"
    return name, None


def delete_prescription_by_id(prescription_id):
    name = ""
    try:
        prescription_to_delete = models.Prescription.objects.get(
            id=prescription_id)
        name = prescription_to_delete.name
        prescription_to_delete.delete()
    except models.Prescription.DoesNotExist:
        return None, "This prescription does not exist"
    return name, None


def fetch_structured_prescriptions():
    structured_prescriptions = {}
    types = list(models.Prescription.objects.all(
    ).values_list("type").distinct())
    for prescription_type in types:
        # returns a tuple i.e why ("medication",)[0] = "medication"
        prescription_type = prescription_type[0]
        structured_prescriptions[prescription_type] = (
            models.Prescription.objects.filter(type=prescription_type).values(
                "id", "name"
            )
        )
    return structured_prescriptions


def update_prescription(prescription_id, prescription_data):
    """
    Update the name, type of prescription
    1. prescription_id not valid uuid
    2. prescription_id does not exist
    3. duplicate name given
    4. successful update
    """
    if not patient_services.is_valid_uuid(prescription_id):
        return "Invalid prescription, it does not exist", status.HTTP_404_NOT_FOUND

    try:
        prescription_to_update = models.Prescription.objects.get(
            id=prescription_id)
    except models.Prescription.DoesNotExist:
        return "Invalid prescription, it does not exist", status.HTTP_404_NOT_FOUND
    prescription_to_update.type = prescription_data["type"]
    prescription_to_update.name = prescription_data["name"]
    try:
        prescription_to_update.save()
    except IntegrityError:
        return (
            "Duplicate entry, prescription with this name exists",
            status.HTTP_409_CONFLICT,
        )
    return None, None
