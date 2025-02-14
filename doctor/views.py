from rest_framework.decorators import api_view, permission_classes
from rest_framework import permissions
from rest_framework.response import Response

# Create your views here.


@api_view(["GET"])
@permission_classes((permissions.AllowAny,))
def treatments(request):
    return Response({"message": "something"})
