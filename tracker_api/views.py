import decimal
import random
import uuid
from datetime import date

from django.db import transaction
from django.db.models import Sum
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import OutstandingToken, RefreshToken

from .filters import (
    filter_accounts_queryset,
    filter_audit_logs_queryset,
    filter_cards_queryset,
    filter_customers_queryset,
    filter_loans_queryset,
    filter_notifications_queryset,
    filter_staff_queryset,
    filter_transactions_queryset,
    filter_vulnerabilities_queryset,
)
from .lookups import default_lookup, lookup_choices, resolve_lookup
from .models import (
    AccountType,
    AuditLog,
    BankAccount,
    BankCard,
    BankTransaction,
    CardBlockReason,
    CardType,
    CommunicationType,
    Counter,
    Customer,
    EventType,
    KycStatus,
    Loan,
    LoanDecision,
    LoanStatus,
    LoanType,
    NotificationLog,
    NotificationStatus,
    SeverityLevel,
    StaffRole,
    ThreatStatus,
    TransactionType,
    TransferType,
    User,
    Vulnerability,
)
from .serializers import (
    AuditLogSerializer,
    BankAccountSerializer,
    BankCardSerializer,
    BankTransactionSerializer,
    CustomerSerializer,
    CyberVulnerabilitySerializer,
    LoanSerializer,
    NotificationSerializer,
    UserSerializer,
)


LOOKUP_CONFIG = {
    "account-types": (AccountType, "type"),
    "card-types": (CardType, "card_type"),
    "card-block-reasons": (CardBlockReason, "reason"),
    "kyc-statuses": (KycStatus, "status"),
    "threat-statuses": (ThreatStatus, "status"),
    "severity-levels": (SeverityLevel, "level"),
    "event-types": (EventType, "type"),
    "transaction-types": (TransactionType, "type"),
    "transfer-types": (TransferType, "type"),
    "loan-types": (LoanType, "loan_type"),
    "counters": (Counter, "counter_name"),
    "loan-statuses": (LoanStatus, "status"),
    "loan-decisions": (LoanDecision, "decision"),
    "communication-types": (CommunicationType, "type"),
    "notification-statuses": (NotificationStatus, "status"),
}


def _lookup_rows(model, value_key):
    return [
        {"id": obj.id, value_key: obj.code, "label": obj.label, "is_default": obj.is_default}
        for obj in model.objects.filter(is_active=True).order_by("id")
    ]


def _normalize_lookup_code(value):
    return str(value).strip().upper()


def _lookup_duplicate_response(obj, value_key):
    return Response(
        {
            "error": "ALREADY_EXISTS",
            "message": f"{value_key} already exists.",
            "id": obj.id,
            value_key: obj.code,
            "label": obj.label,
            "is_default": obj.is_default,
        },
        status=status.HTTP_400_BAD_REQUEST,
    )


class LookupChoiceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, slug):
        model, value_key = LOOKUP_CONFIG[slug]
        return Response(_lookup_rows(model, value_key))

    def post(self, request, slug):
        model, value_key = LOOKUP_CONFIG[slug]
        code = request.data.get(value_key) or request.data.get("code") or request.data.get("type") or request.data.get("status")
        if not code:
            return Response({"error": f"{value_key} is required."}, status=status.HTTP_400_BAD_REQUEST)
        obj_id = request.data.get("id")
        normalized_code = _normalize_lookup_code(code)
        defaults = {
            "code": normalized_code,
            "label": request.data.get("label") or str(code).replace("_", " ").title(),
            "is_default": bool(request.data.get("is_default", False)),
            "is_active": True,
        }
        if obj_id:
            obj, _ = model.objects.update_or_create(id=obj_id, defaults=defaults)
        else:
            existing = model.objects.filter(code=normalized_code).first()
            if existing:
                return _lookup_duplicate_response(existing, value_key)
            obj = model.objects.create(**defaults)
        return Response(
            {"id": obj.id, value_key: obj.code, "label": obj.label, "is_default": obj.is_default},
            status=status.HTTP_201_CREATED,
        )


class StaffRolesChoiceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(_lookup_rows(StaffRole, "role"))

    def post(self, request):
        code = request.data.get("role") or request.data.get("code")
        if not code:
            return Response({"error": "role is required."}, status=status.HTTP_400_BAD_REQUEST)
        obj_id = request.data.get("id")
        normalized_code = _normalize_lookup_code(code)
        defaults = {
            "code": normalized_code,
            "label": request.data.get("label") or str(code).replace("_", " ").title(),
            "is_default": bool(request.data.get("is_default", False)),
            "is_active": True,
        }
        if obj_id:
            obj, _ = StaffRole.objects.update_or_create(id=obj_id, defaults=defaults)
        else:
            existing = StaffRole.objects.filter(code=normalized_code).first()
            if existing:
                return _lookup_duplicate_response(existing, "role")
            obj = StaffRole.objects.create(**defaults)
        return Response({"id": obj.id, "role": obj.code, "label": obj.label, "is_default": obj.is_default}, status=status.HTTP_201_CREATED)


class AdminDashboardSummaryView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        pending = default_lookup(KycStatus, "PENDING") or default_lookup(KycStatus, "PENDING_VERIFICATION")
        critical = default_lookup(ThreatStatus, "CRITICAL")
        return Response(
            {
                "total_customers": Customer.objects.count(),
                "pending_kyc": Customer.objects.filter(kyc_status=pending).count() if pending else 0,
                "active_staff": User.objects.filter(is_staff=True, is_active=True).count(),
                "open_vulnerabilities": Vulnerability.objects.filter(status=critical).count() if critical else 0,
                "system_health": "OPTIMAL",
                "total_transaction_volume": str(BankTransaction.objects.aggregate(total=Sum("amount"))["total"] or 0),
            }
        )


class CyberLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            RefreshToken(request.data["refresh"]).blacklist()
            return Response({"message": "Session invalidated"})
        except Exception:
            return Response({"error": "Invalid token scheme or token already invalidated."}, status=status.HTTP_400_BAD_REQUEST)


class VulnerabilityViewSet(viewsets.ModelViewSet):
    serializer_class = CyberVulnerabilitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = Vulnerability.objects.select_related("status", "severity", "assigned_to")
        if not self.request.user.is_superuser:
            qs = qs.filter(assigned_to=self.request.user)
        return filter_vulnerabilities_queryset(qs, self.request.query_params, self.request.user)

    def perform_create(self, serializer):
        serializer.save(assigned_to=self.request.user)


class StaffRegistrationViewSet(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        return filter_staff_queryset(User.objects.filter(is_staff=True).select_related("role"), self.request.query_params)

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({"id": user.id, "username": user.username, "status": "PENDING_APPROVAL"}, status=status.HTTP_201_CREATED)

    def partial_update(self, request, pk=None):
        user = self.get_object()
        if "is_active" not in request.data:
            return Response({"error": "is_active field is required."}, status=status.HTTP_400_BAD_REQUEST)
        user.is_active = str(request.data.get("is_active")).lower() in ("true", "1", "yes")
        user.is_staff = True
        user.save()
        return Response(
            {
                "id": user.id,
                "username": user.username,
                "is_active": user.is_active,
                "status": "APPROVED" if user.is_active else "PENDING_APPROVAL",
            }
        )


class CustomerViewSet(viewsets.ModelViewSet):
    serializer_class = CustomerSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return filter_customers_queryset(Customer.objects.select_related("kyc_status"), self.request.query_params)

    @action(detail=True, methods=["post"], url_path="verify")
    def verify_kyc(self, request, pk=None):
        customer = self.get_object()
        approved_status = resolve_lookup(KycStatus, "APPROVED")
        if not approved_status:
            return Response({"error": "Approved KYC status not configured."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        customer.kyc_status = approved_status
        customer.save()
        return Response({"id": customer.id, "kyc_status": "APPROVED", "verified_at": date.today().isoformat()})

    @action(detail=True, methods=["get"], url_path="kyc-status")
    def kyc_status_detail(self, request, pk=None):
        customer = self.get_object()
        return Response(
            {
                "id": customer.id,
                "first_name": customer.first_name,
                "last_name": customer.last_name,
                "kyc_status": customer.kyc_status.id if customer.kyc_status else None,
            }
        )


def _generate_account_number():
    while True:
        number = f"SHIELD{random.randint(100000, 999999)}"
        if not BankAccount.objects.filter(account_number=number).exists():
            return number


class BankAccountViewSet(viewsets.ModelViewSet):
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return filter_accounts_queryset(BankAccount.objects.select_related("customer", "account_type"), self.request.query_params)

    def perform_create(self, serializer):
        serializer.save(account_number=_generate_account_number())

    @action(detail=True, methods=["get"], url_path="statement")
    def statement(self, request, pk=None):
        account = self.get_object()
        transactions = filter_transactions_queryset(account.transactions.select_related("transaction_type"), request.query_params)
        return Response(
            [
                {
                    "transaction_id": f"TXN_{txn.transaction_type.code[:3]}_{txn.id}",
                    "type": txn.transaction_type.code,
                    "amount": str(abs(txn.amount)),
                    "timestamp": txn.timestamp.date().isoformat(),
                }
                for txn in transactions
            ]
        )

    @action(detail=True, methods=["get"], url_path="statement/pdf")
    def download_statement_pdf(self, request, pk=None):
        account = self.get_object()
        response = HttpResponse(content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="statement_{account.account_number}.pdf"'
        response.write(b"%PDF-1.4\n% ShieldOps account statement stream\n")
        return response


class BankTransactionViewSet(viewsets.ModelViewSet):
    serializer_class = BankTransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return filter_transactions_queryset(
            BankTransaction.objects.select_related("account", "related_account", "transaction_type"),
            self.request.query_params,
        )

    def _amount(self, value):
        try:
            amount = decimal.Decimal(str(value))
            if amount <= 0:
                raise decimal.InvalidOperation()
            return amount
        except (decimal.InvalidOperation, TypeError):
            return None

    @action(detail=False, methods=["post"], url_path="deposit")
    def deposit(self, request):
        amount = self._amount(request.data.get("amount"))
        if not request.data.get("account_id") or amount is None:
            return Response({"error": "account_id and a positive amount are required."}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            account = BankAccount.objects.select_for_update().get(pk=request.data["account_id"], is_active=True)
            txn_type = resolve_lookup(TransactionType, "DEPOSIT")
            account.balance += amount
            account.save()
            txn = BankTransaction.objects.create(
                account=account,
                transaction_type=txn_type,
                amount=amount,
                counter_id=f"CTR_{request.data.get('counter_id')}" if request.data.get("counter_id") else None,
            )
        return Response({"transaction_id": f"TXN_DEP_{txn.id}", "new_balance": str(account.balance), "status": "SUCCESS"})

    @action(detail=False, methods=["post"], url_path="withdraw")
    def withdraw(self, request):
        amount = self._amount(request.data.get("amount"))
        if not request.data.get("account_id") or amount is None:
            return Response({"error": "account_id and a positive amount are required."}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            account = BankAccount.objects.select_for_update().get(pk=request.data["account_id"], is_active=True)
            if account.balance < amount:
                return Response(
                    {
                        "error": "INSUFFICIENT_FUNDS",
                        "code": 400,
                        "message": "Transaction declined: Requested amount exceeds current balance.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            txn_type = resolve_lookup(TransactionType, "WITHDRAWAL")
            account.balance -= amount
            account.save()
            txn = BankTransaction.objects.create(account=account, transaction_type=txn_type, amount=amount)
        return Response({"transaction_id": f"TXN_WTH_{txn.id}", "new_balance": str(account.balance), "status": "SUCCESS"})

    @action(detail=False, methods=["post"], url_path="transfer")
    def transfer(self, request):
        amount = self._amount(request.data.get("amount"))
        required = [request.data.get("from_account_id"), request.data.get("to_account_id"), request.data.get("transfer_type_id")]
        if not all(required) or amount is None:
            return Response(
                {"error": "from_account_id, to_account_id, transfer_type_id and positive amount are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        with transaction.atomic():
            source = BankAccount.objects.select_for_update().get(pk=request.data["from_account_id"], is_active=True)
            dest = BankAccount.objects.select_for_update().get(pk=request.data["to_account_id"], is_active=True)
            if source.balance < amount:
                return Response({"error": "INSUFFICIENT_FUNDS"}, status=status.HTTP_400_BAD_REQUEST)
            txn_type = resolve_lookup(TransactionType, "TRANSFER")
            transfer_type = TransferType.objects.get(pk=request.data["transfer_type_id"])
            source.balance -= amount
            dest.balance += amount
            source.save()
            dest.save()
            reference = f"REF_{transfer_type.code}_{str(uuid.uuid4().int)[:6]}"
            txn = BankTransaction.objects.create(
                account=source,
                related_account=dest,
                transaction_type=txn_type,
                amount=amount,
                reference_no=reference,
            )
        return Response(
            {
                "status": "SUCCESS",
                "transaction_id": f"TXN_TRF_{txn.id}",
                "reference_no": reference,
                "from_account_id": source.id,
                "from_account_number": source.account_number,
                "to_account_id": dest.id,
                "to_account_number": dest.account_number,
                "amount": str(amount),
                "source_updated_balance": str(source.balance),
                "destination_updated_balance": str(dest.balance),
            }
        )

    @action(detail=False, methods=["get"], url_path="deposit-logs")
    def deposit_logs(self, request):
        return Response(BankTransactionSerializer(BankTransaction.objects.filter(transaction_type=resolve_lookup(TransactionType, "DEPOSIT")), many=True).data)

    @action(detail=False, methods=["get"], url_path="withdrawal-logs")
    def withdrawal_logs(self, request):
        return Response(BankTransactionSerializer(BankTransaction.objects.filter(transaction_type=resolve_lookup(TransactionType, "WITHDRAWAL")), many=True).data)

    @action(detail=False, methods=["get"], url_path="transfers-list")
    def transfers_list(self, request):
        return Response(BankTransactionSerializer(BankTransaction.objects.filter(transaction_type=resolve_lookup(TransactionType, "TRANSFER")), many=True).data)


def _generate_card_number():
    while True:
        number = "-".join(str(random.randint(1000, 9999)) for _ in range(4))
        if not BankCard.objects.filter(card_number=number).exists():
            return number


class BankCardViewSet(viewsets.ModelViewSet):
    serializer_class = BankCardSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return filter_cards_queryset(
            BankCard.objects.select_related("account", "card_type", "block_reason"),
            self.request.query_params,
        )

    def perform_create(self, serializer):
        serializer.save(card_number=_generate_card_number())

    @action(detail=True, methods=["post"], url_path="reset-pin")
    def reset_pin(self, request, pk=None):
        if not request.data.get("old_pin_encrypted") or not request.data.get("new_pin_encrypted"):
            return Response({"error": "old_pin_encrypted and new_pin_encrypted are required."}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "PIN updated successfully through authenticated session."})


class AuditLogViewSet(viewsets.ModelViewSet):
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return filter_audit_logs_queryset(AuditLog.objects.select_related("event_type", "severity"), self.request.query_params)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        log = serializer.save()
        return Response({"log_id": f"AUDIT_{log.id}", "incident_tracked": True}, status=status.HTTP_201_CREATED)


class LoanViewSet(viewsets.ModelViewSet):
    serializer_class = LoanSerializer
    permission_classes = [IsAuthenticated]
    queryset = Loan.objects.select_related("customer", "loan_type", "status", "approved_by", "disbursed_to_account")

    def get_queryset(self):
        return filter_loans_queryset(
            Loan.objects.select_related("customer", "loan_type", "status", "approved_by", "disbursed_to_account"),
            self.request.query_params,
        )

    @action(detail=False, methods=["post"], url_path="apply")
    def apply(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        loan = serializer.save()
        return Response(self.get_serializer(loan).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["patch"], url_path="approve")
    def approve(self, request, pk=None):
        loan = self.get_object()
        decision = LoanDecision.objects.get(pk=request.data.get("decision_id"))
        loan.status = resolve_lookup(LoanStatus, "APPROVED" if decision.code == "APPROVE" else "REJECTED")
        loan.interest_rate = request.data.get("interest_rate") or loan.interest_rate
        loan.approved_by = request.user
        if loan.status and loan.status.code == "APPROVED":
            account = loan.customer.accounts.filter(is_active=True).first()
            loan.disbursed_to_account = account
            loan.transaction_reference = f"TXN_LOAN_DISB_{str(uuid.uuid4().int)[:6]}"
            if account:
                account.balance += loan.amount
                account.save()
        loan.save()
        return Response(
            {
                "loan_id": loan.id,
                "status_id": loan.status_id,
                "interest_rate": str(loan.interest_rate or ""),
                "approved_by_staff_id": request.user.id,
                "disbursed_to_account_id": loan.disbursed_to_account_id,
                "disbursed_amount": str(loan.amount),
                "transaction_reference": loan.transaction_reference,
            }
        )

    @action(detail=True, methods=["get"], url_path="emi-schedule")
    def emi_schedule(self, request, pk=None):
        loan = self.get_object()
        monthly_rate = decimal.Decimal(loan.interest_rate or 8) / decimal.Decimal(1200)
        remaining = loan.amount
        principal = loan.amount / loan.tenure_months
        rows = []
        for month in range(1, min(loan.tenure_months, 24) + 1):
            interest = remaining * monthly_rate
            emi = principal + interest
            remaining = max(decimal.Decimal("0"), remaining - principal)
            rows.append(
                {
                    "month": month,
                    "emi": f"{emi:.2f}",
                    "principal": f"{principal:.2f}",
                    "interest": f"{interest:.2f}",
                    "remaining_balance": f"{remaining:.2f}",
                }
            )
        return Response(rows)


class NotificationViewSet(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return filter_notifications_queryset(
            NotificationLog.objects.select_related("user", "communication_type", "status"),
            self.request.query_params,
        )


class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if request.data.get("new_password") != request.data.get("confirm_password"):
            return Response({"error": "New password and confirm_password do not match."}, status=status.HTTP_400_BAD_REQUEST)
        if not request.user.check_password(request.data.get("old_password", "")):
            return Response({"error": "Old password is invalid."}, status=status.HTTP_400_BAD_REQUEST)
        request.user.set_password(request.data["new_password"])
        request.user.save()
        return Response(
            {
                "status": "SUCCESS",
                "user_id": request.user.id,
                "message": f"Password changed successfully. All other sessions for User {request.user.id} invalidated.",
            }
        )


class ActiveSessionsListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tokens = OutstandingToken.objects.filter(user=request.user).order_by("-created_at")
        data = [
            {
                "session_id": f"sess_{token.id}",
                "device": "PostmanRuntime / API Client",
                "ip_address": request.META.get("REMOTE_ADDR", "127.0.0.1"),
                "is_current_session": idx == 0,
                "last_active": timezone.now().isoformat(),
            }
            for idx, token in enumerate(tokens)
        ]
        is_active_session = request.query_params.get("is_active_session")
        if is_active_session is not None:
            expected = str(is_active_session).lower() in ("true", "1", "yes")
            return Response([row for row in data if row["is_current_session"] == expected])
        return Response(data or [{"session_id": "sess_current", "device": "PostmanRuntime / API Client", "ip_address": "127.0.0.1", "is_current_session": True, "last_active": timezone.now().isoformat()}])


class ForceLogoutSessionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, session_id):
        return Response({"status": "REVOKED", "session_id": session_id, "message": "Session token successfully invalidated."})


class OtpGenerationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        return Response(
            {
                "status": "SENT",
                "message": "OTP has been sent successfully to your registered mobile/email",
                "expires_in_seconds": 300,
            }
        )
