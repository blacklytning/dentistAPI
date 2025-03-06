import datetime
from . import models
from . import serializers
from . import utils
from authentication.models import User


def fetch_followups_by_date(date: datetime.datetime.date):
    """
    Returns list of all the followups for the given date
    """
    followups_for_date = models.FollowUp.objects.select_related(
        "complaint", "complaint__user", "complaint__user__details"
    ).filter(date=date)
    formatted_followups = []
    for followup in followups_for_date:
        formatted_followups.append(
            {
                "name": followup.complaint.user.name,
                "age": utils.get_age(followup.complaint.user.details.date_of_birth),
                "phonenumber": followup.complaint.user.phonenumber,
                "time": followup.time,
                "followup": followup.title,
            }
        )
    if not formatted_followups:
        return ["No followups today"]
    return formatted_followups


def serialize_medical_details(medical_data):
    """
    1. Check identity validity (name, phonenumber)
    2. Check medical_details validity (allergies, illnesses, smoking, tobacco, drinking)
    """
    # Check for errors in identity
    identity = serializers.PhoneNameSerializer(data=medical_data.get("identity"))
    if not identity.is_valid():
        return None, identity.error_messages

    # Check for errors in medical_data
    print(type(medical_data.get("medical_details")))
    medical_details = serializers.MedicalDetailsSerializer(
        data=medical_data.get("medical_details")
    )
    if not medical_details.is_valid():
        print(medical_details.error_messages)
        return None, medical_details.error_messages

    serialized_data = {
        "identity": identity.data,
        "medical_details": medical_details.data,
    }
    return serialized_data, None


def add_medical_details(data):
    """
    1. Creates medical details for first time
    1. Updates medical details if details already filled
    """
    try:
        user_details = User.objects.select_related("details").get(
            name=data["identity"].get("name"),
            phonenumber=data["identity"].get("phonenumber"),
        )
    except User.DoesNotExist:
        return "User not found"

    # Bringing allergies and illnesses to csv format instead of lists
    allergies, illnesses = "", ""
    for allergy in data["medical_details"]["allergies"]:
        allergies += allergy + ","
    for illness in data["medical_details"]["illnesses"]:
        illnesses += illness + ","
    user_details.details.illnesses = illnesses[:-1]
    user_details.details.allergies = allergies[:-1]
    user_details.details.smoking = data["medical_details"]["smoking"]
    user_details.details.tobacco = data["medical_details"]["tobacco"]
    user_details.details.drinking = data["medical_details"]["drinking"]
    user_details.details.save()
    return None
