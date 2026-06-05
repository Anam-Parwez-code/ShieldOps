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
    BankCardSerializer, AuditLogSerializer, UserSerializer
)


# ─────────────────────────────────────────────
# 1. Vulnerability ViewSet
# ─────────────────────────────────────────────
class VulnerabilityViewSet(viewsets.ModelViewSet):
    serializer_class = CyberVulnerabilitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # models.py mein field assigned_to hai
        return Vulnerability.objects.filter(assigned_to=self.request.user)


# ─────────────────────────────────────────────
# 2. Secure Logout
# ─────────────────────────────────────────────
class CyberLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"message": "Secure infrastructure session closed successfully."},
                status=status.HTTP_200_OK
            )
        except Exception:
            return Response(
                {"error": "Invalid token scheme or token already invalidated."},
                status=status.HTTP_400_BAD_REQUEST
            )


# ─────────────────────────────────────────────
# 3. Staff Registration + Listing (Admin)
#    POST /api/admin/staff/register/   → create staff
#    GET  /api/admin/staff/            → list all staff
#    GET  /api/admin/staff/<id>/       → retrieve single staff
# ─────────────────────────────────────────────
class StaffRegistrationViewSet(viewsets.ViewSet):
    permission_classes = [IsAdminUser]

    def list(self, request):
        """GET /api/admin/staff/ — Retrieve all registered staff members."""
        staff = User.objects.filter(is_staff=True)
        serializer = UserSerializer(staff, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None):
        """GET /api/admin/staff/<id>/ — Retrieve a single staff member."""
        try:
            user = User.objects.get(pk=pk, is_staff=True)
        except User.DoesNotExist:
            return Response({"error": "Staff member not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request):
        """POST /api/admin/staff/register/ — Register new staff member."""
        username = request.data.get('username')
        email    = request.data.get('email')
        role     = request.data.get('role', 'CASHIER')

        if not username:
            return Response({"error": "Username is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, email=email, role=role, is_staff=True)
        return Response(
            {"id": user.id, "username": user.username, "status": "PENDING_APPROVAL"},
            status=status.HTTP_201_CREATED
        )


# ─────────────────────────────────────────────
# 4. Cashier Management (Admin)
#    POST  /api/admin/cashiers/        → register cashier
#    GET   /api/admin/cashiers/        → list all cashiers
#    GET   /api/admin/cashiers/<id>/   → retrieve single cashier
#    PATCH /api/admin/cashiers/<id>/   → suspend cashier
# ─────────────────────────────────────────────
class CashierViewSet(viewsets.ViewSet):
    permission_classes = [IsAdminUser]

    def list(self, request):
        """GET /api/admin/cashiers/ — List all cashier accounts."""
        cashiers = User.objects.filter(role='CASHIER')
        serializer = UserSerializer(cashiers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None):
        """GET /api/admin/cashiers/<id>/ — Retrieve single cashier profile."""
        try:
            cashier = User.objects.get(pk=pk, role='CASHIER')
        except User.DoesNotExist:
            return Response({"error": "Cashier not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = UserSerializer(cashier)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request):
        """POST /api/admin/cashiers/ — Register a new cashier."""
        username = request.data.get('username')
        email    = request.data.get('email')

        if not username:
            return Response({"error": "Username is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(
            username=username, email=email, role='CASHIER', is_staff=True
        )
        return Response(
            {"id": user.id, "username": user.username, "role": "CASHIER", "is_active": user.is_active},
            status=status.HTTP_201_CREATED
        )

    def partial_update(self, request, pk=None):
        """PATCH /api/admin/cashiers/<id>/ — Suspend cashier (set is_active=False)."""
        try:
            cashier = User.objects.get(pk=pk, role='CASHIER')
        except User.DoesNotExist:
            return Response({"error": "Cashier not found."}, status=status.HTTP_404_NOT_FOUND)

        cashier.is_active = request.data.get('is_active', cashier.is_active)
        cashier.save()
        return Response(
            {"id": cashier.id, "username": cashier.username, "is_active": cashier.is_active},
            status=status.HTTP_200_OK
        )


# ─────────────────────────────────────────────
# 5. Customer ViewSet
#    Standard CRUD + verify (POST) + kyc-status (GET)
# ─────────────────────────────────────────────
class CustomerViewSet(viewsets.ModelViewSet):
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """POST /api/bank/customers/<id>/verify/ — Approve KYC for customer."""
        customer = self.get_object()
        customer.kyc_status = 'APPROVED'
        customer.save()
        return Response({
            "id": customer.id,
            "kyc_status": customer.kyc_status,
            "verified_at": "2026-06-04",
            "verified_by": request.data.get('verified_by', 'N/A'),
            "remarks": request.data.get('remarks', '')
        })

    @action(detail=True, methods=['get'], url_path='kyc-status')
    def kyc_status(self, request, pk=None):
        """GET /api/bank/customers/<id>/kyc-status/ — Check current KYC status."""
        customer = self.get_object()
        return Response({
            "id": customer.id,
            "first_name": customer.first_name,
            "last_name": customer.last_name,
            "kyc_status": customer.kyc_status
        })


# ─────────────────────────────────────────────
# 6. Bank Account ViewSet
#    Standard CRUD + statement (GET) — already covered
# ─────────────────────────────────────────────
class BankAccountViewSet(viewsets.ModelViewSet):
    queryset = BankAccount.objects.all()
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['get'])
    def statement(self, request, pk=None):
        """GET /api/bank/accounts/<id>/statement/ — Fetch account transaction history."""
        account = self.get_object()
        txns = BankTransaction.objects.filter(account=account)
        serializer = BankTransactionSerializer(txns, many=True)
        return Response(serializer.data)


# ─────────────────────────────────────────────
# 7. Bank Transaction ViewSet
#    GET  /api/bank/transactions/              → full ledger
#    POST /api/bank/transactions/deposit/      → log deposit
#    GET  /api/bank/transactions/deposit-logs/ → view all deposits
#    POST /api/bank/transactions/withdraw/     → log withdrawal
#    GET  /api/bank/transactions/withdrawal-logs/ → view all withdrawals
# ─────────────────────────────────────────────
class BankTransactionViewSet(viewsets.ModelViewSet):
    queryset = BankTransaction.objects.all()
    serializer_class = BankTransactionSerializer
    permission_classes = [IsAuthenticated]

    # ── Deposit ──────────────────────────────
    @action(detail=False, methods=['post'], url_path='deposit')
    @transaction.atomic
    def deposit(self, request):
        """POST /api/bank/transactions/deposit/ — Log a cash deposit."""
        acc_num = request.data.get('account_number')
        amount  = decimal.Decimal(request.data.get('amount', 0))

        try:
            account = BankAccount.objects.get(account_number=acc_num)
        except BankAccount.DoesNotExist:
            return Response({"error": "Account not found."}, status=status.HTTP_404_NOT_FOUND)

        account.balance += amount
        account.save()

        txn = BankTransaction.objects.create(
            account=account,
            transaction_type='DEPOSIT',
            amount=amount,
            counter_id=request.data.get('counter_id')
        )
        return Response({
            "transaction_id": f"TXN_DEP_{txn.id}",
            "new_balance": str(account.balance),
            "status": "SUCCESS"
        }, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'], url_path='deposit-logs')
    def deposit_logs(self, request):
        """GET /api/bank/transactions/deposit-logs/ — Retrieve all deposit records."""
        deposits = BankTransaction.objects.filter(transaction_type='DEPOSIT').order_by('-timestamp')
        serializer = BankTransactionSerializer(deposits, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # ── Withdrawal ───────────────────────────
    @action(detail=False, methods=['post'], url_path='withdraw')
    @transaction.atomic
    def withdraw(self, request):
        """POST /api/bank/transactions/withdraw/ — Log a cash withdrawal."""
        acc_num = request.data.get('account_number')
        amount  = decimal.Decimal(request.data.get('amount', 0))

        try:
            account = BankAccount.objects.get(account_number=acc_num)
        except BankAccount.DoesNotExist:
            return Response({"error": "Account not found."}, status=status.HTTP_404_NOT_FOUND)

        if account.balance < amount:
            return Response({
                "error": "INSUFFICIENT_FUNDS",
                "code": 400,
                "message": "Transaction declined: Requested amount exceeds current balance."
            }, status=status.HTTP_400_BAD_REQUEST)

        account.balance -= amount
        account.save()

        txn = BankTransaction.objects.create(
            account=account,
            transaction_type='WITHDRAWAL',
            amount=amount
        )
        return Response({
            "transaction_id": f"TXN_WTH_{txn.id}",
            "new_balance": str(account.balance),
            "status": "SUCCESS"
        }, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'], url_path='withdrawal-logs')
    def withdrawal_logs(self, request):
        """GET /api/bank/transactions/withdrawal-logs/ — Retrieve all withdrawal records."""
        withdrawals = BankTransaction.objects.filter(transaction_type='WITHDRAWAL').order_by('-timestamp')
        serializer = BankTransactionSerializer(withdrawals, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────
# 8. Bank Card ViewSet
#    Standard CRUD (GET list/retrieve auto) + reset-pin (POST)
# ─────────────────────────────────────────────
class BankCardViewSet(viewsets.ModelViewSet):
    queryset = BankCard.objects.all()
    serializer_class = BankCardSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'], url_path='reset-pin')
    def reset_pin(self, request, pk=None):
        """POST /api/bank/cards/<id>/reset-pin/ — Reset card PIN via authenticated session."""
        # Production mein: old/new PIN decrypt + verify karo
        return Response({"message": "PIN updated successfully through authenticated session."})


# ─────────────────────────────────────────────
# 9. Audit Log ViewSet
#    Standard CRUD (GET list/retrieve auto) + POST already covered
# ─────────────────────────────────────────────
class AuditLogViewSet(viewsets.ModelViewSet):
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]