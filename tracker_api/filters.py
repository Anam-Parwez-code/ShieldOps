from django.db.models import Q
from django.utils.dateparse import parse_date

from .lookups import resolve_lookup
from .models import (
    StaffRole, KycStatus, ThreatStatus, SeverityLevel,
    AccountType, EventType, TransactionType,
)


def filter_staff_queryset(queryset, params):
    role = params.get('role') or params.get('role_id')
    if role:
        role_obj = resolve_lookup(StaffRole, role)
        if role_obj:
            queryset = queryset.filter(role=role_obj)

    is_active = params.get('is_active')
    if is_active is not None:
        val = str(is_active).lower() in ('true', '1', 'yes')
        queryset = queryset.filter(is_active=val)

    search = params.get('search')
    if search:
        queryset = queryset.filter(
            Q(username__icontains=search) | Q(email__icontains=search)
        )

    ordering = params.get('ordering')
    if ordering in ('date_joined', '-date_joined', 'username', '-username'):
        queryset = queryset.order_by(ordering)

    return queryset


def filter_customers_queryset(queryset, params):
    kyc = params.get('kyc_status') or params.get('kyc_status_id')
    if kyc:
        kyc_obj = resolve_lookup(KycStatus, kyc)
        if kyc_obj:
            queryset = queryset.filter(kyc_status=kyc_obj)

    search = params.get('search')
    if search:
        queryset = queryset.filter(
            Q(first_name__icontains=search)
            | Q(last_name__icontains=search)
            | Q(email__icontains=search)
        )

    ordering = params.get('ordering')
    if ordering in ('created_at', '-created_at', 'first_name', '-first_name'):
        queryset = queryset.order_by(ordering)

    return queryset


def filter_vulnerabilities_queryset(queryset, params, user=None):
    status = params.get('status') or params.get('status_id')
    if status:
        status_obj = resolve_lookup(ThreatStatus, status)
        if status_obj:
            queryset = queryset.filter(status=status_obj)

    severity = params.get('severity') or params.get('severity_id')
    if severity:
        sev_obj = resolve_lookup(SeverityLevel, severity)
        if sev_obj:
            queryset = queryset.filter(severity=sev_obj)

    assigned = params.get('assigned_to')
    if assigned == 'me' and user and user.is_authenticated:
        queryset = queryset.filter(assigned_to=user)

    search = params.get('search')
    if search:
        queryset = queryset.filter(threat_title__icontains=search)

    ordering = params.get('ordering')
    if ordering in ('target_date', '-target_date', 'id', '-id'):
        queryset = queryset.order_by(ordering)

    return queryset


def filter_accounts_queryset(queryset, params):
    account_type = params.get('account_type') or params.get('account_type_id')
    if account_type:
        type_obj = resolve_lookup(AccountType, account_type)
        if type_obj:
            queryset = queryset.filter(account_type=type_obj)

    is_active = params.get('is_active')
    if is_active is not None:
        val = str(is_active).lower() in ('true', '1', 'yes')
        queryset = queryset.filter(is_active=val)

    customer = params.get('customer')
    if customer:
        queryset = queryset.filter(customer_id=customer)

    search = params.get('search')
    if search:
        queryset = queryset.filter(account_number__icontains=search)

    return queryset


def filter_transactions_queryset(queryset, params):
    txn_type = params.get('transaction_type') or params.get('transaction_type_id')
    if txn_type:
        type_obj = resolve_lookup(TransactionType, txn_type)
        if type_obj:
            queryset = queryset.filter(transaction_type=type_obj)

    from_date = params.get('from_date')
    if from_date:
        parsed = parse_date(from_date)
        if parsed:
            queryset = queryset.filter(timestamp__date__gte=parsed)

    to_date = params.get('to_date')
    if to_date:
        parsed = parse_date(to_date)
        if parsed:
            queryset = queryset.filter(timestamp__date__lte=parsed)

    ordering = params.get('ordering')
    if ordering in ('timestamp', '-timestamp', 'amount', '-amount'):
        queryset = queryset.order_by(ordering)
    elif not ordering:
        queryset = queryset.order_by('-timestamp')

    return queryset


def filter_audit_logs_queryset(queryset, params):
    event = params.get('event_type') or params.get('event_type_id')
    if event:
        event_obj = resolve_lookup(EventType, event)
        if event_obj:
            queryset = queryset.filter(event_type=event_obj)

    severity = params.get('severity') or params.get('severity_id')
    if severity:
        sev_obj = resolve_lookup(SeverityLevel, severity)
        if sev_obj:
            queryset = queryset.filter(severity=sev_obj)

    return queryset.order_by('-timestamp')
