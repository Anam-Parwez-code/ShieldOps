from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CyberVulnerability
from .serializers import CyberVulnerabilitySerializer

class VulnerabilityViewSet(viewsets.ModelViewSet):
    """
    Core APIs for threat life cycle management.
    Restricted to authorized auditors only.
    """
    serializer_class = CyberVulnerabilitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return CyberVulnerability.objects.filter(assigned_to=self.request.user)

class CyberLogoutView(APIView):
    """
    Accepts dynamic refresh tokens to commit them directly to the database blacklist.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Secure infrastructure session closed successfully."}, status=status.HTTP_200_OK)
        except Exception:
            return Response({"error": "Invalid token scheme or token already invalidated."}, status=status.HTTP_400_BAD_REQUEST)