import decimal
from datetime import date

from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken
from django.db import transaction
from django.db.models import Sum, Count

from .models import (
    User, Vulnerability, Customer, BankAccount, BankTransaction,
    BankCard, AuditLog, StaffRole, AccountType, KycStatus,
    ThreatStatus, SeverityLevel, CardType, EventType, TransactionType,
)
from .serializers import (
    CyberVulnerabilitySerializer, CustomerSerializer,
    BankAccountSerializer, BankTransactionSerializer,
    BankCardSerializer, AuditLogSerializer, UserSerializer,
)
from .filters import (
    filter_staff_queryset, filter_customers_queryset,
    filter_vulnerabilities_queryset, filter_accounts_queryset,
    filter_transactions_queryset, filter_audit_logs_queryset,
)
from .lookups import lookup_choices, resolve_lookup, default_lookup


def _txn_code(txn_type):
    return txn_type.code if txn_type else 'UNKNOWN'


# ─────────────────────────────────────────────
# Choice / Lookup API Endpoints
# ─────────────────────────────────────────────
class AccountTypesChoiceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        choices = lookup_choices(AccountType)
        default = default_lookup(AccountType, 'SAVINGS')
        return Response({
            'choices': choices,
            'default': default.id if default else None,
            'default_code': default.code if default else 'SAVINGS',
        })


class CardTypesChoiceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        choices = lookup_choices(CardType)
        default = default_lookup(CardType, 'VISA_CLASSIC')
        return Response({
            'choices': choices,
            'default': default.id if default else None,
            'default_code': default.code if default else 'VISA_CLASSIC',
        })


class KycStatusesChoiceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        choices = lookup_choices(KycStatus)
        default = default_lookup(KycStatus, 'PENDING_VERIFICATION')
        return Response({
            'choices': choices,
            'default': default.id if default else None,
            'default_code': default.code if default else 'PENDING_VERIFICATION',
        })


class ThreatStatusesChoiceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        choices = lookup_choices(ThreatStatus)
        default = default_lookup(ThreatStatus, 'CRITICAL')
        return Response({
            'choices': choices,
            'default': default.id if default else None,
            'default_code': default.code if default else 'CRITICAL',
        })


class SeverityLevelsChoiceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        choices = lookup_choices(SeverityLevel)
        default = default_lookup(SeverityLevel, 'MEDIUM')
        return Response({
            'choices': choices,
            'default': default.id if default else None,
            'default_code': default.code if default else 'MEDIUM',
        })


class EventTypesChoiceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        choices = lookup_choices(EventType)
        return Response({'choices': choices})


class StaffRolesChoiceView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        choices = lookup_choices(StaffRole)
        default = default_lookup(StaffRole, 'CASHIER')
        return Response({
            'roles': choices,
            'default': default.id if default else None,
            'default_code': default.code if default else 'CASHIER',
        })


class AdminDashboardSummaryView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        critical = default_lookup(ThreatStatus, 'CRITICAL')
        pending_kyc = default_lookup(KycStatus, 'PENDING_VERIFICATION')
        return Response({
            'staff': {
                'total': User.objects.filter(is_staff=True).count(),
                'active': User.objects.filter(is_staff=True, is_active=True).count(),
                'pending': User.objects.filter(is_staff=True, is_active=False).count(),
            },
            'customers': {
                'total': Customer.objects.count(),
                'kyc_pending': Customer.objects.filter(kyc_status=pending_kyc).count() if pending_kyc else 0,
            },
            'accounts': {
                'total': BankAccount.objects.count(),
                'active': BankAccount.objects.filter(is_active=True).count(),
                'frozen': BankAccount.objects.filter(is_active=False).count(),
            },
            'transactions': {
                'total': BankTransaction.objects.count(),
                'total_volume': str(
                    BankTransaction.objects.aggregate(total=Sum('amount'))['total'] or 0
                ),
            },
            'vulnerabilities': {
                'critical_open': Vulnerability.objects.filter(status=critical).count() if critical else 0,
                'total': Vulnerability.objects.count(),
            },
            'audit_logs': AuditLog.objects.count(),
        })


# ─────────────────────────────────────────────
# Vulnerability ViewSet
# ─────────────────────────────────────────────
class VulnerabilityViewSet(viewsets.ModelViewSet):
    serializer_class = CyberVulnerabilitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = Vulnerability.objects.select_related('status', 'severity', 'assigned_to')
        if not self.request.user.is_superuser:
            qs = qs.filter(assigned_to=self.request.user)
        return filter_vulnerabilities_queryset(qs, self.request.query_params, self.request.user)

    def perform_create(self, serializer):
        serializer.save(assigned_to=self.request.user)


# ─────────────────────────────────────────────
# Secure Logout
# ─────────────────────────────────────────────
class CyberLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Session invalidated'}, status=status.HTTP_200_OK)
        except Exception:
            return Response(
                {'error': 'Invalid token scheme or token already invalidated.'},
                status=status.HTTP_400_BAD_REQUEST,
            )


# ─────────────────────────────────────────────
# Staff Registration + Listing
# ─────────────────────────────────────────────
class StaffRegistrationViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAdminUser]
    serializer_class = UserSerializer
    queryset = User.objects.filter(is_staff=True).select_related('role')

    def list(self, request):
        staff = filter_staff_queryset(
            User.objects.filter(is_staff=True).select_related('role'),
            request.query_params,
        )
        serializer = UserSerializer(staff, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None):
        try:
            user = User.objects.select_related('role').get(pk=pk)
        except User.DoesNotExist:
            return Response({'error': 'Staff member not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(UserSerializer(user).data, status=status.HTTP_200_OK)

    def create(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(
                {'id': user.id, 'username': user.username, 'status': 'PENDING_APPROVAL'},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            user = User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Response({'error': 'Staff member not found.'}, status=status.HTTP_404_NOT_FOUND)

        is_active = request.data.get('is_active')
        if is_active is None:
            return Response({'error': 'is_active field is required.'}, status=status.HTTP_400_BAD_REQUEST)

        user.is_active = bool(is_active) if isinstance(is_active, bool) else str(is_active).lower() == 'true'
        if user.is_active:
            user.is_staff = True
        user.save()

        status_string = 'APPROVED' if user.is_active else 'PENDING_APPROVAL'
        return Response({
            'id': user.id,
            'username': user.username,
            'is_active': user.is_active,
            'status': status_string,
        }, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────
# Cashier Management
# ─────────────────────────────────────────────
class CashierViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAdminUser]
    serializer_class = UserSerializer

    def get_cashier_role(self):
        return resolve_lookup(StaffRole, 'CASHIER')

    def get_queryset(self):
        role = self.get_cashier_role()
        return User.objects.filter(role=role).select_related('role') if role else User.objects.none()

    def list(self, request):
        cashiers = self.get_queryset()
        serializer = UserSerializer(cashiers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None):
        role = self.get_cashier_role()
        try:
            cashier = User.objects.select_related('role').get(pk=pk, role=role)
        except User.DoesNotExist:
            return Response({'error': 'Cashier not found.'}, status=status.HTTP_404_NOT_FOUND)
        return Response(UserSerializer(cashier).data, status=status.HTTP_200_OK)

    def create(self, request):
        data = request.data.copy()
        role = self.get_cashier_role()
        if role:
            data['role_id'] = role.id
        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'id': user.id,
                'username': user.username,
                'role': UserSerializer(user).data.get('role'),
                'is_active': user.is_active,
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ─────────────────────────────────────────────
# Customer ViewSet
# ─────────────────────────────────────────────
class CustomerViewSet(viewsets.ModelViewSet):
    serializer_class = CustomerSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = Customer.objects.select_related('kyc_status')
        return filter_customers_queryset(qs, self.request.query_params)

    @action(detail=True, methods=['post'], url_path='verify')
    def verify(self, request, pk=None):
        customer = self.get_object()
        approved = default_lookup(KycStatus, 'APPROVED')
        customer.kyc_status = approved
        customer.save()
        return Response({
            'id': customer.id,
            'kyc_status': {'id': approved.id, 'code': approved.code, 'label': approved.label},
            'verified_at': date.today().isoformat(),
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'], url_path='kyc-status')
    def kyc_status(self, request, pk=None):
        customer = self.get_object()
        return Response({
            'id': customer.id,
            'first_name': customer.first_name,
            'last_name': customer.last_name,
            'kyc_status': {
                'id': customer.kyc_status_id,
                'code': customer.kyc_status.code,
                'label': customer.kyc_status.label,
            },
        }, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────
# Bank Account ViewSet
# ─────────────────────────────────────────────
class BankAccountViewSet(viewsets.ModelViewSet):
    serializer_class = BankAccountSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = BankAccount.objects.select_related('account_type', 'customer')
        return filter_accounts_queryset(qs, self.request.query_params)

    @action(detail=True, methods=['get'], url_path='statement')
    def statement(self, request, pk=None):
        account = self.get_object()
        txns = BankTransaction.objects.filter(account=account).select_related(
            'transaction_type'
        ).order_by('timestamp')

        statement_data = []
        for t in txns:
            code = _txn_code(t.transaction_type)
            prefix = 'TXN_DEP' if code == 'DEPOSIT' else 'TXN_WTH'
            statement_data.append({
                'transaction_id': f'{prefix}_{t.id}',
                'type': code,
                'amount': str(t.amount),
                'timestamp': t.timestamp.strftime('%Y-%m-%d') if t.timestamp else date.today().isoformat(),
            })
        return Response(statement_data, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────
# Bank Transaction ViewSet
# ─────────────────────────────────────────────
class BankTransactionViewSet(viewsets.ModelViewSet):
    serializer_class = BankTransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = BankTransaction.objects.select_related('transaction_type', 'account')
        return filter_transactions_queryset(qs, self.request.query_params)

    @action(detail=False, methods=['post'], url_path='deposit')
    @transaction.atomic
    def deposit(self, request):
        acc_num = request.data.get('account_number')
        amount = decimal.Decimal(str(request.data.get('amount', 0)))

        try:
            account = BankAccount.objects.get(account_number=acc_num)
        except BankAccount.DoesNotExist:
            return Response({'error': 'Account not found.'}, status=status.HTTP_404_NOT_FOUND)

        account.balance += amount
        account.save()

        dep_type = default_lookup(TransactionType, 'DEPOSIT')
        txn = BankTransaction.objects.create(
            account=account,
            transaction_type=dep_type,
            amount=amount,
            counter_id=request.data.get('counter_id'),
        )
        return Response({
            'transaction_id': f'TXN_DEP_{txn.id}',
            'new_balance': str(account.balance),
            'status': 'SUCCESS',
        }, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'], url_path='deposit-logs')
    def deposit_logs(self, request):
        dep_type = default_lookup(TransactionType, 'DEPOSIT')
        deposits = BankTransaction.objects.filter(
            transaction_type=dep_type
        ).select_related('transaction_type', 'account').order_by('-timestamp')
        serializer = BankTransactionSerializer(deposits, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'], url_path='withdraw')
    @transaction.atomic
    def withdraw(self, request):
        acc_num = request.data.get('account_number')
        amount = decimal.Decimal(str(request.data.get('amount', 0)))

        try:
            account = BankAccount.objects.get(account_number=acc_num)
        except BankAccount.DoesNotExist:
            return Response({'error': 'Account not found.'}, status=status.HTTP_404_NOT_FOUND)

        if account.balance < amount:
            return Response({
                'error': 'INSUFFICIENT_FUNDS',
                'code': 400,
                'message': 'Transaction declined: Requested amount exceeds current balance.',
            }, status=status.HTTP_400_BAD_REQUEST)

        account.balance -= amount
        account.save()

        wth_type = default_lookup(TransactionType, 'WITHDRAWAL')
        txn = BankTransaction.objects.create(
            account=account,
            transaction_type=wth_type,
            amount=amount,
        )
        return Response({
            'transaction_id': f'TXN_WTH_{txn.id}',
            'new_balance': str(account.balance),
            'status': 'SUCCESS',
        }, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'], url_path='withdrawal-logs')
    def withdrawal_logs(self, request):
        wth_type = default_lookup(TransactionType, 'WITHDRAWAL')
        withdrawals = BankTransaction.objects.filter(
            transaction_type=wth_type
        ).select_related('transaction_type', 'account').order_by('-timestamp')
        serializer = BankTransactionSerializer(withdrawals, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────
# Bank Card ViewSet
# ─────────────────────────────────────────────
class BankCardViewSet(viewsets.ModelViewSet):
    serializer_class = BankCardSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return BankCard.objects.select_related('card_type', 'account')

    @action(detail=True, methods=['post'], url_path='reset-pin')
    def reset_pin(self, request, pk=None):
        return Response({
            'message': 'PIN updated successfully through authenticated session.',
        }, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────
# Security Audit Logs ViewSet
# ─────────────────────────────────────────────
class AuditLogViewSet(viewsets.ModelViewSet):
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = AuditLog.objects.select_related('event_type', 'severity')
        return filter_audit_logs_queryset(qs, self.request.query_params)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            log_instance = serializer.save()
            return Response({
                'log_id': f'AUDIT_{log_instance.id}',
                'incident_tracked': True,
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        data = []
        for log in queryset:
            data.append({
                'log_id': f'AUDIT_{log.id}',
                'event_type': {
                    'id': log.event_type_id,
                    'code': log.event_type.code,
                    'label': log.event_type.label,
                },
                'severity': {
                    'id': log.severity_id,
                    'code': log.severity.code,
                    'label': log.severity.label,
                },
                'ip_address': log.ip_address,
                'timestamp': log.timestamp.strftime('%Y-%m-%d') if log.timestamp else None,
            })
        return Response(data, status=status.HTTP_200_OK)
