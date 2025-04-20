import datetime

from django.db import IntegrityError
from django.http import HttpResponse
from rest_framework import permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

import authentication.jsonwebtokens as jsonwebtokens
import authentication.validation as validation
from authentication import models as auth

from . import models, serializers, services, utils
from .serializers import ComplaintSerializer, DetailsSerializer


@api_view(["GET"])
@permission_classes((permissions.AllowAny,))
def patients(request, phonenumber=None, name=None):
    """
    --------HERE NAME IN THE PATH SHOULD BE IN LOWERCASE-SNAKECASE--------
    eg: John Doe (normal name) -> john_doe(lowercase-snakecase)
    1. Name and Phonenumber
    2. Name
    3. Phonenumber
    """
    # Make sure user is admin or doctor
    token, error = jsonwebtokens.is_authorized(
        request.headers["Authorization"].split(" ")[1], set(["admin", "dentist"])
    )
    if error:
        return Response(
            {"error": error},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    if request.method == "GET":
        # Convert data to proper format
        if phonenumber:
            is_valid_phonenumber: validation.FieldValidity = (
                validation.validate_phonenumber(int(phonenumber))
            )

            if not is_valid_phonenumber["valid"]:
                return Response(
                    {"error": is_valid_phonenumber["error"]},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        if name:
            name = services.capitalize_name(name, snake_case=True)

        patients, no_match_error = {}, ""
        if phonenumber and name:
            patients, no_match_error = services.fetch_patients_with_phone_and_name(
                phonenumber, name
            )
        elif phonenumber:
            patients, no_match_error = services.fetch_patients_with_phone(phonenumber)
        elif name:
            patients, no_match_error = services.fetch_patients_with_name(name)
        else:
            return Response(
                {"error": "Provide atleast name or phonenumber to search"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if no_match_error:
            return Response({"error": no_match_error}, status=status.HTTP_200_OK)
        return Response({"patients": patients}, status=status.HTTP_200_OK)

    # JWT authentication
    token, error = jsonwebtokens.is_authorized(
        request.headers["Authorization"].split(" ")[1], set(["dentist", "admin"])
    )
    if error:
        return Response(
            {"error": error},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # Fetch all patients
    all_patients = models.Details.objects.all().values_list()
    return Response({"patients": all_patients}, status=status.HTTP_200_OK)


@api_view(["GET", "POST"])
@permission_classes((permissions.AllowAny,))
def details(request):
    """
    POST:
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
    GET:
        Returns patient details. Requires Authorization header with admin role.
    """
    if request.method == "POST":
        token, error = jsonwebtokens.is_authorized(
            request.headers["Authorization"].split(" ")[1], set(["admin"])
        )
        if error:
            return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)

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
                name=services.capitalize_name(request.data["details"]["name"]),
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
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        models.Details.objects.create(
            id=user_object,
            date_of_birth=serializer.validated_data["date_of_birth"],
            address=serializer.validated_data["address"],
            gender=serializer.validated_data["gender"],
        )

        return Response(
            {"message": "Details have been registered"}, status=status.HTTP_200_OK
        )

    elif request.method == "GET":
        try:
            token = request.headers["Authorization"].split(" ")[1]
        except (KeyError, IndexError):
            return Response({"error": "Authorization token missing"}, status=401)

        payload, error = jsonwebtokens.is_authorized(token, set(["patient"]))
        if error:
            return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)

        if "phonenumber" not in payload:
            return Response({"error": "Phone number not found in token"}, status=400)

        try:
            user = auth.User.objects.get(phonenumber=payload["phonenumber"])
            details = models.Details.objects.get(id=user)
            serialized = DetailsSerializer(details)
            return Response(
                {
                    "phonenumber": user.phonenumber,
                    "name": user.name,
                    "role": user.role,
                    "details": serialized.data,
                },
                status=200,
            )
        except auth.User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)
        except models.Details.DoesNotExist:
            return Response({"error": "User details not found"}, status=404)


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
        request.headers["Authorization"].split(" ")[1], set(["admin", "dentist"])
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
                    "id": complaint.id,
                    "patient_id": complaint.user.id,
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
                phonenumber=phonenumber,
                name=services.capitalize_name(serializer.data["name"]),
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


@api_view(["GET", "POST", "PUT", "DELETE"])
@permission_classes((permissions.AllowAny,))
def diagnosis(request, complaint_id=None, id=None):
    """
    1. GET: fetch by complaint_id
    2. POST: add diagnosis for a particular complaint
    Expected JSON:
    {
        "treatment": "21ed0219-6358-4555-9efe-b996d2e94508",
        "complaint": "1002931f-d1b3-4408-9147-2e3432c67cc2",
        "tooth_number": 44
    }
    3. PUT: change treatment (tooth no. change not possible only according to UI)
    Expected JSON:
    {
      "treatment": "e886b9aa-1ffb-45af-9db2-86e177ef6b78",
      "id": "e886b9aa-1ffb-45af-9db2-86e177ef6b78",
      "tooth_number": 44
    }
    4. DELETE: deleting diagnosis for a tooth
    """
    if request.method == "GET":
        token, error = jsonwebtokens.is_authorized(
            request.headers.get("Authorization").split(" ")[1],
            set(["dentist"]),
        )
        if error:
            return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)
    if request.method == "GET":
        if complaint_id:
            diagnoses = services.fetch_diagnosis_by_complaint(complaint_id)
            return Response({"diagnosis": diagnoses}, status=status.HTTP_200_OK)

        return Response(
            {"error": "Invalid complaint, no diagnosis present"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    elif request.method == "POST":
        # serialize incoming data
        diagnosis_serializer = serializers.DiagnosisSerializer(data=request.data)
        if not diagnosis_serializer.is_valid():
            return Response(
                {"error": "Invalid fields, check all fields properly"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # create record in db
        error, error_code = services.create_diagnosis(diagnosis_serializer.data)
        if error:
            return Response({"error": error}, status=error_code)
        return Response({"message": "Diagnosis has been saved!"})

    elif request.method == "PUT":
        diagnosis_update = serializers.DiagnosisUpdateSerializer(data=request.data)
        if not diagnosis_update.is_valid():
            return Response({"error": "Invalid entry, recheck fields"})
        error, error_code = services.update_diagnosis(diagnosis_update.data)
        if error:
            return Response({"error": error}, status=error_code)
        return Response({"message": "Diagnosis has been updated!"})

    elif request.method == "DELETE":
        if not id:
            return Response(
                {"error": "Diagnosis was not deleted"}, status=status.HTTP_404_NOT_FOUND
            )
        tooth_number, treatment, error = services.delete_diagnosis(id)
        if error:
            return Response({"error": error}, status=status.HTTP_404_NOT_FOUND)
        return Response(
            {"success": f"Tooth {tooth_number}'s {treatment} diagnosis deleted"},
            status=status.HTTP_200_OK,
        )


@api_view(["GET", "POST", "PUT"])
@permission_classes((permissions.AllowAny,))
def followups(request, complaint_id=None, date=None):
    """
    1. GET:
        a. Fetch all followups for that day (for admin-dentist waiting list)
        - 200 OK: Everything fine
        - 401 UNAUTHORIZED: Inappropriate role
    2. POST:
        a. Add followup to the database
    Expected JSON: {
        complaint_id: <valid UUID from database>,
        followup: {
            "title": "meeting 2",
            "description": "" (empty, info about what will happen in followup, filled after followup complete),
            "date": "2025-12-05",
            "time": "13:30:00",
            "completed": False,
            "number": 1
        }
    }
    3. PUT:
    - After followup, when doctor updates the description i.else:
    they type out what they did during the followup
    - Update time incase, it doesn't match
    - Expected JSON : {
        "id": "55adcbae-df2b-4fee-87b6-d16bf170b04f",
        "description": "performed RCT, fixed tooth 23, 12"
        "time": "14:30:00" (even if not changed, ask frontend to send)
        "date": "2025-12-13" (even if not changed, ask frontend to send)
    }
    """
    if request.method == "GET":
        token, error = jsonwebtokens.is_authorized(
            request.headers.get("Authorization").split(" ")[1],
            set(["dentist", "admin"]),
        )
        if error:
            return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)

        # fetching followups for patient's complaint
        if complaint_id:
            # the url already verifies that UUID is valid so no checking needed
            # fetch all followups for that complaint_id
            past_followups = services.fetch_followups_by_complaint(complaint_id)
            return Response(
                {"followups": past_followups},
                status=status.HTTP_200_OK,
            )
        if date:
            # fetching followups for a particular date
            today_followups = services.fetch_followups_by_date(date)
            return Response({"followups": today_followups}, status=status.HTTP_200_OK)

        # fetching followups for dashboard
        today_date = datetime.datetime.now().date()
        today_followups = services.fetch_followups_by_date(today_date)
        return Response({"followups": today_followups}, status=status.HTTP_200_OK)

    # FOR POST AND PUT you need to be dentist
    token, error = jsonwebtokens.is_authorized(
        request.headers.get("Authorization").split(" ")[1],
        set(["dentist"]),
    )
    if error:
        return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)

    elif request.method == "POST":
        followup_serializer = serializers.FollowupSerializer(
            data=request.data["followup"]
        )
        if not followup_serializer.is_valid():
            return Response(
                {"error": "Invaild fields, check all the fields properly"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        error = services.create_followup(
            request.data["complaint_id"], followup_serializer.data
        )
        if error:
            return Response({"error": error}, status=status.HTTP_404_NOT_FOUND)

        return Response(
            {"success": "Followup has been created"}, status=status.HTTP_200_OK
        )
    elif request.method == "PUT":
        followup_update_serializer = serializers.FollowupUpdateSerializer(
            data=request.data
        )
        if not followup_update_serializer.is_valid():
            return Response(
                {"error": "Invaild fields, check all the fields properly"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        error = services.update_followup(followup_update_serializer.data)
        if error:
            return Response({"error": error}, status=status.HTTP_404_NOT_FOUND)

        return Response(
            {"success": "Followup has been updated"}, status=status.HTTP_200_OK
        )


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
                {"name": token.get("name"), "phonenumber": token.get("phonenumber")}
            )
            if error:
                return Response({"error": error}, status=status.HTTP_400_BAD_REQUEST)

        medical_details, error = services.fetch_medical_details(
            data["name"],
            data["phonenumber"],
        )
        if error:
            return Response({"error": error}, status=status.HTTP_404_NOT_FOUND)
        return Response({"medical_details": medical_details}, status=status.HTTP_200_OK)

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
            status=status.HTTP_200_OK,
        )


@api_view(["GET", "POST"])
@permission_classes((permissions.AllowAny,))
def patient_history(request, patient_id=None):
    """
    Get list of all complaints and followups for a particular patient
    """
    token, error = jsonwebtokens.is_authorized(
        request.headers.get("Authorization").split(" ")[1],
        set(["dentist", "admin"]),
    )
    if error:
        return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)
    if request.method == "GET":
        if not patient_id:
            return Response(
                {"error": "Couldn't find patient's history"},
                status=status.HTTP_404_NOT_FOUND,
            )
        patient_history, error = services.fetch_complaint_and_followup_history(
            patient_id
        )
        if error:
            return Response({"error": error}, status=status.HTTP_404_NOT_FOUND)
        return Response({"history": patient_history}, status=status.HTTP_200_OK)


@api_view(["GET", "POST", "PUT"])
@permission_classes((permissions.AllowAny,))
def bills(request, complaint_id=None):
    """
    1. GET: fetch bills for a complaint using complaint_id
    2. POST: save bill for the first time
    Expected JSON:
    {
        "complaint": "728d2379-292f-4039-8983-24895e716c77",
        "full_bill": 5000,
        "discount": 1000,

    }
    3. PUT: make updates to the bill if needed
    Expected JSON:
    {
        "id": "fe48a6e0-e490-421e-bac0-eddea9478198"
        "full_bill": 4000,
        "discount": 1000,
    }
    """

    token, error = jsonwebtokens.is_authorized(
        request.headers.get("Authorization").split(" ")[1],
        set(["dentist"]),
    )
    if error:
        return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == "GET":
        if not complaint_id:
            return Response(
                {"error": "Can't fetch bill without knowing complaint"},
                status=status.HTTP_404_NOT_FOUND,
            )
        bill, error, error_code = services.fetch_bill(complaint_id)
        if error:
            return Response({"error": error}, status=error_code)
        return Response({"bill": bill}, status=status.HTTP_200_OK)

    elif request.method == "POST":
        # serialize input
        bills_serializer = serializers.BillSerializer(data=request.data)
        if not bills_serializer.is_valid():
            return Response(
                {"error": "Invalid fields, check all fields again"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # save the record
        error, error_code = services.create_bill(bills_serializer.data)
        if error:
            return Response({"error": error}, status=error_code)
        return Response(
            {"message": "Bill has been saved!"},
            status=status.HTTP_200_OK,
        )

    elif request.method == "PUT":
        bills_update_serializer = serializers.BillUpdateSerializer(data=request.data)
        if not bills_update_serializer.is_valid():
            return Response(
                {"error": "Invalid fields, check all fields again"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # save the record
        error = services.update_bill(bills_update_serializer.data)
        if error:
            return Response({"error": error}, status=status.HTTP_404_NOT_FOUND)
        return Response(
            {"message": "Bill has been saved!"},
            status=status.HTTP_200_OK,
        )


@api_view(["GET", "POST", "PUT", "DELETE"])
@permission_classes((permissions.AllowAny,))
def prescription(
    request, patient_prescription_id=None, complaint_id=None, sitting=None
):
    """
    - Prescription is mapped to sitting and not a complaint
    1. GET: Get the prescription for a particular sitting
    2. POST:
    Expected JSON:
    {
        "complaint": <UUID>,
        "sitting": 0,
        "prescription": prescription_id,
        "days": 3,
        "dosage": "OD"
    }
    3. PUT
    {
        "id": <UUID>,
        "prescription": prescription_id,
        "days": 3,
        "dosage": "OD"
    }
    4. DELETE using user_prescription_id
    """
    token, error = jsonwebtokens.is_authorized(
        request.headers.get("Authorization").split(" ")[1],
        set(["dentist"]),
    )
    if error:
        return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == "GET":
        if not complaint_id or sitting is None:
            return Response(
                {"error": "Couldn't fetch prescriptions for undefined sitting"},
                status=status.HTTP_404_NOT_FOUND,
            )
        prescription, error = services.fetch_patients_prescriptions(
            complaint_id, sitting
        )
        if error:
            return Response({"error": error}, status=status.HTTP_404_NOT_FOUND)
        return Response({"prescription": prescription})

    if request.method == "POST":
        # serialize the data
        patient_prescription_serializer = serializers.PatientPrescriptionSerializer(
            data=request.data
        )
        if not patient_prescription_serializer.is_valid():
            return Response(
                {"error": "Invalid field, check all fields properly"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # create record
        error, error_code = services.create_patient_prescription(
            patient_prescription_serializer.data
        )
        if error:
            return Response({"error": error}, status=error_code)
        return Response({"success": "Saved prescription!"})

    if request.method == "PUT":
        # serialize data
        patient_prescription_update_serializer = (
            serializers.PatientPrescriptionUpdateSerializer(data=request.data)
        )
        if not patient_prescription_update_serializer.is_valid():
            return Response(
                {"error": "Invalid field, check all fields properly"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # update record
        error, error_code = services.update_patients_prescription(
            patient_prescription_update_serializer.data
        )
        if error:
            return Response({"error": error}, status=error_code)
        return Response({"success": "Updated prescription!"})

    if request.method == "DELETE":
        name, error = services.delete_patient_prescription(patient_prescription_id)
        if error:
            return Response({"error": error}, status=status.HTTP_404_NOT_FOUND)
        return Response({"success": f"Deleted prescription {name}!"})


@api_view(["GET"])
@permission_classes((permissions.AllowAny,))
def pdf_prescription(request, complaint_id=None, sitting=None):
    """
    Generates a pdf prescription for a sitting
    """

    token, error = jsonwebtokens.is_authorized(
        request.headers.get("Authorization").split(" ")[1],
        set(["dentist"]),
    )
    if error:
        return Response({"error": error}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == "GET":
        if not complaint_id or sitting is None:
            print("404 control here?")
            return Response(
                {"error": "Couldn't print prescription"},
                status=status.HTTP_404_NOT_FOUND,
            )
        # get prescription data
        prescriptions, error = services.fetch_patients_prescriptions(
            complaint_id, sitting
        )
        if error:
            return Response({"error": error}, status=status.HTTP_404_NOT_FOUND)

        # get next followup
        followup_and_personal_data = (
            services.fetch_followup_and_personal_data_for_prescription_pdf(
                complaint_id, sitting
            )
        )

        response = HttpResponse(content_type="application/pdf")
        response["Content-Disposition"] = 'inline; filename="prescription.pdf"'

        services.create_pdf(response, followup_and_personal_data, prescriptions)
        return response
