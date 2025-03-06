from rest_framework import serializers
from . import models


class DetailsSerializer(serializers.ModelSerializer):
    """
    Serializer for Details
    date_of_birth: <Date>
    address: <String>
    Gender: <M | F | T | O>
    """

    class Meta:
        model = models.Details
        exclude = ["id", "allergies", "illnesses", "tobacco", "smoking", "drinking"]


class MedicalDetailsSerializer(serializers.Serializer):
    """
    allergies: <String>
    illnesses: <String>
    smoking: <Bool>
    tobacco: <Bool>
    drinking: <Bool>
    """

    allergies = serializers.ListField(child=serializers.CharField(), default=[])
    illnesses = serializers.ListField(child=serializers.CharField(), default=[])
    smoking = serializers.BooleanField(default=False)
    tobacco = serializers.BooleanField(default=False)
    drinking = serializers.BooleanField(default=False)


class ComplaintSerializer(serializers.Serializer):
    """
    chief_complaint: <String> Description of complaint
    name: <String> Name of the person
    """

    chief_complaint = serializers.CharField()
    name = serializers.CharField()


class PhoneNameSerializer(serializers.Serializer):
    """
    phonenumber: <LongInt> Phonenumber of patient
    name: <String> Name of patient
    """

    phonenumber = serializers.IntegerField()
    name = serializers.CharField()
