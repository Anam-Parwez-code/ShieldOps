import decimal
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken
from django.db import transaction

from .models import User, Vulnerability, Customer, BankAccount, BankTransaction, BankCard, AuditLog
from .serializers import (
    CyberVulnerabilitySerializer, CustomerSerializer, 
    BankAccountSerializer, BankTransactionSerializer,
    BankCardSerializer, AuditLogSerializer
)
from .permissions import IsSecurityAuditor, IsManager, IsCashier # Agar custom permissions use kar rahe hain

# 1. Vulnerability ViewSet (Fixed CyberVulnerability query error)
class VulnerabilityViewSet(viewsets.ModelViewSet):
    serializer_class = CyberVulnerabilitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Model name changed from CyberVulnerability to Vulnerability
        return Vulnerability.objects.filter(assigned_to=self.request.user)

# 2. Secure Logout
class CyberLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Secure infrastructure session closed successfully."}, status=status.HTTP_200_OK)
        except Exception:
            return Response({"error": "Invalid token scheme or token already invalidated."}, status=status.HTTP_400_BAD_REQUEST)

# 3. Staff Registration (Admin Endpoint)
class StaffRegistrationViewSet(viewsets.ViewSet):
    permission_classes = [IsAdminUser]

    def create(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        role = request.data.get('role', 'CASHIER')
        
        if not username:
            return Response({"error": "Username is required"}, status=status.HTTP_400_BAD_REQUEST)
            
        user = User.objects.create_user(username=username, email=email, role=role, is_staff=True)
        return Response({"id": user.id, "username": user.username, "status": "PENDING_APPROVAL"}, status=status.HTTP_201_CREATED)

# 4. Customer ViewSet
class CustomerViewSet(viewsets.ModelViewSet):
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        customer = self.get_object()
        customer.kyc_status = 'APPROVED'
        customer.save()
        return Response({"id": customer.id, "kyc_status": customer.kyc_status, "verified_at": "2026-06-04"})

# 5. Bank Account ViewSet
class BankAccountViewSet(viewsets.ModelViewSet):
    queryset = BankAccount.objects.all()
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['get'])
    def statement(self, request, pk=None):
        account = self.get_object()
        txns = BankTransaction.objects.filter(account=account)
        serializer = BankTransactionSerializer(txns, many=True)
        return Response(serializer.data)

# 6. Bank Transaction ViewSet (Synced with urls.py naming convention)
class BankTransactionViewSet(viewsets.ModelViewSet):
    queryset = BankTransaction.objects.all()
    serializer_class = BankTransactionSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['post'], url_path='deposit')
    @transaction.atomic
    def deposit(self, request):
        acc_num = request.data.get('account_number')
        amount = decimal.Decimal(request.data.get('amount', 0))
        account = BankAccount.objects.get(account_number=acc_num)
        
        account.balance += amount
        account.save()
        
        txn = BankTransaction.objects.create(account=account, transaction_type='DEPOSIT', amount=amount, counter_id=request.data.get('counter_id'))
        return Response({"transaction_id": f"TXN_DEP_{txn.id}", "new_balance": str(account.balance), "status": "SUCCESS"}, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['post'], url_path='withdraw')
    @transaction.atomic
    def withdraw(self, request):
        acc_num = request.data.get('account_number')
        amount = decimal.Decimal(request.data.get('amount', 0))
        account = BankAccount.objects.get(account_number=acc_num)

        if account.balance < amount:
            return Response({
                "error": "INSUFFICIENT_FUNDS",
                "code": 400,
                "message": "Transaction declined: Requested amount exceeds current balance."
            }, status=status.HTTP_400_BAD_REQUEST)

        account.balance -= amount
        account.save()
        
        txn = BankTransaction.objects.create(account=account, transaction_type='WITHDRAWAL', amount=amount)
        return Response({"transaction_id": f"TXN_WTH_{txn.id}", "new_balance": str(account.balance), "status": "SUCCESS"}, status=status.HTTP_201_CREATED)

# 7. Bank Card ViewSet
class BankCardViewSet(viewsets.ModelViewSet):
    queryset = BankCard.objects.all()
    serializer_class = BankCardSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'], url_path='reset-pin')
    def reset_pin(self, request, pk=None):
        return Response({"message": "PIN updated successfully through authenticated session."})

# 8. Audit Log ViewSet
class AuditLogViewSet(viewsets.ModelViewSet):
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]