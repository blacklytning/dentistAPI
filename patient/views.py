from rest_framework.decorators import api_view, permission_classes
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework import status
from django.db import IntegrityError
import datetime
from authentication import models as auth
import authentication.jsonwebtokens as jsonwebtokens
import authentication.validation as validation
from .serializers import DetailsSerializer, ComplaintSerializer
from . import models
from . import services
from . import utils


@api_view(["GET"])
@permission_classes((permissions.AllowAny,))
def patients(request, phonenumber=None, active=None):
    """
    1. Retrieve single patient
    2. Retrieve many patients
    """
    # Make sure user is admin or doctor

    if request.method == "GET":
        # Fetch single patient
        if phonenumber:
            patient = models.Details.objects.filter(
                id__phonenumber=phonenumber
            ).values()
            return Response({"patient": patient}, status=status.HTTP_200_OK)

    # JWT authentication
    token, error = jsonwebtokens.is_authorized(
        request.headers["Authorization"].split(
            " ")[1], set(["dentist", "admin"])
    )
    if error:
        return Response(
            {"error": error},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # Fetch all patients
    all_patients = models.Details.objects.all().values_list()
    return Response({"patients": all_patients}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes((permissions.AllowAny,))
def details(request):
    """
    Expected JSON
        "phonenumber": "7880589921"
        "details": {
            "name": "john doe",
            "date_of_birth": "1990-02-14",
            "address": "avenue street, gotham city",
            "gender": "M",
        }

    - create a user object first
    - create details object first
    """
    if request.method == "POST":
        # Make sure user is admin
        token, error = jsonwebtokens.is_authorized(
            request.headers["Authorization"].split(" ")[1], set(["admin"])
        )
        if error:
            return Response(
                {"error": error},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Case 2
        phonenumber = request.data.get("phonenumber")
        is_valid_phonenumber: validation.FieldValidity = (
            validation.validate_phonenumber(int(phonenumber))
        )

        if not is_valid_phonenumber["valid"]:
            return Response(
                {"error": is_valid_phonenumber["error"]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user_object = auth.User.objects.create(
                phonenumber=phonenumber,
                name=services.capitalize_name(
                    request.data.get("details").get("name")),
                role="patient",
                password="",
            )
        except IntegrityError:
            return Response(
                {"error": "Account exists for this name and phonenumber"},
                status=status.HTTP_409_CONFLICT,
            )

        serializer = DetailsSerializer(data=request.data.get("details"))
        if not serializer.is_valid():
            return Response(
                serializer.error_messages, status=status.HTTP_400_BAD_REQUEST
            )

        models.Details.objects.create(
            id=user_object,
            date_of_birth=serializer.data["date_of_birth"],
            address=serializer.data["address"],
            gender=serializer.data["gender"],
        )

        # get role
        return Response(
            {"message": "Details have been registered"}, status=status.HTTP_200_OK
        )


@api_view(["GET", "POST"])
@permission_classes((permissions.AllowAny,))
def complaints(request):
    """
    GET REQUEST:
    1. FOR DASHBOARD: Get the list of all active complaints (for that day)
    Expected JSON:

        {
            name: <String>,
            phonenumber,
            time:,
            age: ,
            complaint
        }

    2. FOR LIST:

    POST REQUEST:
    Registering complaints/appointments for patients

    Flow:
    1. Check if invoker is admin
        - 401 UNAUTHORIZED: Invalid JWT
        - 401 UNAUTHORIZED: Not admin
    2. Validate phonenumber
        - 400 BAD REQUEST: invalid phonenumber
    3. Validate complaint
        - 400 BAD REQUEST: invalid complaint details
    4. Fetch user_id
        - 404 NOT FOUND: User not registered
    5. Register complaint

    Expected JSON

        {
            "phonenumber": "7880589921",
            complaint: {
                "name": "John Doe",
                "chief_complaint": "tooth-ache",
            }
        }


    """
    # Make sure user is admin or dentist
    token, error = jsonwebtokens.is_authorized(
        request.headers["Authorization"].split(
            " ")[1], set(["admin", "dentist"])
    )
    if error:
        return Response(
            {"error": error},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    if request.method == "GET":
        # Fetch active patients
        all_complaints = models.Complaint.objects.select_related(
            "user", "user__details"
        ).filter(date=datetime.datetime.now().date())

        complaints = []
        for complaint in all_complaints:
            complaints.append(
                {
                    "name": complaint.user.name,
                    "age": utils.get_age(complaint.user.details.date_of_birth),
                    "phonenumber": complaint.user.phonenumber,
                    "time": complaint.time,
                    "complaint": complaint.complaint,
                }
            )

        return Response({"complaints": complaints}, status=status.HTTP_200_OK)

    if request.method == "POST":
        # Validate phonenumber
        phonenumber = request.data.get("phonenumber")
        is_valid_phonenumber: validation.FieldValidity = (
            validation.validate_phonenumber(int(phonenumber))
        )
        if not is_valid_phonenumber["valid"]:
            return Response(
                {"error": is_valid_phonenumber["error"]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate complaint
        serializer = ComplaintSerializer(data=request.data.get("complaint"))
        if not serializer.is_valid():
            return Response(
                serializer.error_messages, status=status.HTTP_400_BAD_REQUEST
            )

        # Fetch user_id
        try:
            user = auth.User.objects.get(
                phonenumber=phonenumber, name=serializer.data["name"]
            )
        except auth.User.DoesNotExist:
            return Response(
                {"error": "User is not registered. Register them please"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Register Complaint
        models.Complaint.objects.create(
            user=user,
            complaint=serializer.data["chief_complaint"],
        )

        # REMEMBER: When complaint is diagnosed sitting is done, billing is done
        # set user's "active" to False So that we can fetch people who are still
        # "active" the next day for doctor, incase someone is left out
        # Or some followup has been delayed.
        # Also whenever the billing is done (flow ends), update the day in the database for their complaint

        return Response({"message": "complaint registered"}, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes((permissions.AllowAny,))
def followups(request):
    """
    1. GET:
        a. Fetch all followups for that day (for admin-dentist waiting list)
        - 200 OK: Everything fine
        - 401 UNAUTHORIZED: Inappropriate role
    2. POST:
        a. Add followup to the database

    """
    if request.method == "GET":
        token, error = jsonwebtokens.is_authorized(
            request.headers.get("Authorization").split(" ")[1],
            set(["dentist", "admin"]),
        )
        if error:
            return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)

        today_date = datetime.datetime.now().date()
        today_followups = services.fetch_followups_by_date(today_date)
    return Response({"followups": today_followups}, status=status.HTTP_200_OK)


@api_view(["GET", "POST"])
@permission_classes((permissions.AllowAny,))
def medical_details(request, name=None, phonenumber=None):
    """

    1. GET:
        a. Patient seeing self's medical details (p/medical_details/)
        b. Doctor fetching a patient's medical details'(p/medical_details/<phone>/<name>)
        --------HERE NAME IN THE PATH SHOULD BE IN LOWERCASE-SNAKECASE--------
        eg: John Doe (normal name) -> john_doe(lowercase-snakecase)

        - 200 OK: Everything fine
    2. POST:
        - Add medical_details to the database
        Expected JSON:
        {
            identity: {
                name: John Doe,
                phonenumber: 9654396543,
            },
            medical_details: {
                allergies: [pollen, peanuts],
                illnesses: [migraine, sinus],
                smoking: false,
                drinking: true,
                tobacco: false,
            }
        }

    """
    if request.method == "GET":
        # Case when doctor is viewing patient's medical_details
        data = {}  # Empty init for scope adjustment
        if phonenumber and name:
            token, error = jsonwebtokens.is_authorized(
                request.headers.get("Authorization").split(" ")[1],
                set(["dentist"]),
            )
            if error:
                return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)

            name = services.capitalize_name(name, snake_case=True)
            data, error = services.serialize_identity(
                {"name": name, "phonenumber": phonenumber}
            )
            if error:
                return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)

        # Case when patient is viewing their own medical_details
        else:
            # Here we are only interested in getting token, not authorization
            token, error = jsonwebtokens.is_authorized(
                request.headers.get("Authorization").split(" ")[1],
            )
            data, error = services.serialize_identity(
                {"name": token.get("name"),
                 "phonenumber": token.get("phonenumber")}
            )
            if error:
                return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)

        medical_details, error = services.fetch_medical_details(
            data["name"],
            data["phonenumber"],
        )
        if error:
            return Response({"error": error}, status=status.HTTP_404_NOT_FOUND)
        return Response({"medical_detials": medical_details}, status=status.HTTP_200_OK)

    if request.method == "POST":
        token, error = jsonwebtokens.is_authorized(
            request.headers.get("Authorization").split(" ")[1],
            set(["dentist"]),
        )
        if error:
            return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)

        data, error = services.serialize_medical_details(request.data)
        if error:
            return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)

        error = services.add_medical_details(data)
        if error:
            return Response({"error": error}, status=status.HTTP_404_NOT_FOUND)

        return Response(
            {"message": "Medical details have been saved"},
            status=status.HTTP_201_CREATED,
        )


@api_view(["GET", "POST"])
@permission_classes((permissions.AllowAny,))
def patient_history(request):
    """
    Get list of all complaints and followups for a particular patient
    """
    if request.method == "GET":
        phonenumber = request.GET.get("phonenumber")
        name = request.GET.get("name")
        if phonenumber and name:
            pass
    pass
