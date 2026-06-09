from rest_framework import serializers
from django.contrib.auth.hashers import make_password

from .models import (
    User, StaffRole, Vulnerability, Customer, BankAccount,
    BankTransaction, BankCard, AuditLog,
    AccountType, KycStatus, ThreatStatus, SeverityLevel,
    CardType, EventType, TransactionType,
)
from .lookups import resolve_lookup, default_lookup


class LookupField(serializers.Field):
    """Read: expose {id, code, label}. Write: accept id or code."""

    def __init__(self, lookup_model, **kwargs):
        self.lookup_model = lookup_model
        super().__init__(**kwargs)

    def to_representation(self, value):
        if value is None:
            return None
        return {'id': value.id, 'code': value.code, 'label': value.label}

    def to_internal_value(self, data):
        if data is None:
            return None
        if isinstance(data, dict):
            data = data.get('id') or data.get('code')
        obj = resolve_lookup(self.lookup_model, data)
        if not obj:
            raise serializers.ValidationError(f'Invalid {self.lookup_model.__name__}: {data}')
        return obj


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    role = LookupField(StaffRole, required=False, allow_null=True)
    role_id = serializers.IntegerField(write_only=True, required=False)
    status = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'role', 'role_id', 'is_active',
            'is_staff', 'date_joined', 'password', 'confirm_password', 'status',
        ]
        read_only_fields = ['id', 'date_joined', 'status']

    def get_status(self, obj):
        return 'APPROVED' if obj.is_active else 'PENDING_APPROVAL'

    def validate(self, attrs):
        if attrs.get('password') and attrs.get('confirm_password'):
            if attrs['password'] != attrs['confirm_password']:
                raise serializers.ValidationError({'password': 'Password and Confirm Password do not match.'})
        role_id = self.initial_data.get('role_id')
        role_code = self.initial_data.get('role')
        if role_id and not attrs.get('role'):
            attrs['role'] = resolve_lookup(StaffRole, role_id)
        elif role_code and not attrs.get('role'):
            attrs['role'] = resolve_lookup(StaffRole, role_code)
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password', None)
        raw_password = validated_data.pop('password')
        validated_data['password'] = make_password(raw_password)
        validated_data['is_active'] = False
        validated_data['is_staff'] = True
        if not validated_data.get('role'):
            validated_data['role'] = default_lookup(StaffRole, 'CASHIER')
        return super().create(validated_data)


class CyberVulnerabilitySerializer(serializers.ModelSerializer):
    status = LookupField(ThreatStatus, required=False)
    status_id = serializers.IntegerField(write_only=True, required=False)
    severity = LookupField(SeverityLevel, required=False, allow_null=True)
    severity_id = serializers.IntegerField(write_only=True, required=False)
    assigned_to = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'threat_title', 'target_date', 'status', 'status_id',
            'severity', 'severity_id', 'completion_date', 'remarks', 'assigned_to',
        ]

    def validate(self, attrs):
        for field, model, default_code in [
            ('status', ThreatStatus, 'CRITICAL'),
            ('severity', SeverityLevel, 'MEDIUM'),
        ]:
            fid = f'{field}_id'
            if self.initial_data.get(fid) and not attrs.get(field):
                attrs[field] = resolve_lookup(model, self.initial_data[fid])
            if field in attrs and attrs[field] is None:
                attrs[field] = default_lookup(model, default_code)
        if not attrs.get('status') and self.instance is None:
            attrs['status'] = default_lookup(ThreatStatus, 'CRITICAL')
        return attrs


class CustomerSerializer(serializers.ModelSerializer):
    kyc_status = LookupField(KycStatus, required=False)
    kyc_status_id = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = Customer
        fields = [
            'id', 'first_name', 'last_name', 'email', 'phone',
            'kyc_status', 'kyc_status_id', 'created_at',
        ]
        read_only_fields = ['created_at']

    def validate(self, attrs):
        if self.initial_data.get('kyc_status_id') and not attrs.get('kyc_status'):
            attrs['kyc_status'] = resolve_lookup(KycStatus, self.initial_data['kyc_status_id'])
        if not attrs.get('kyc_status') and self.instance is None:
            attrs['kyc_status'] = default_lookup(KycStatus, 'PENDING_VERIFICATION')
        return attrs


class BankAccountSerializer(serializers.ModelSerializer):
    account_type = LookupField(AccountType, required=False)
    account_type_id = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = BankAccount
        fields = [
            'id', 'customer', 'account_number', 'account_type',
            'account_type_id', 'balance', 'is_active',
        ]

    def validate(self, attrs):
        if self.initial_data.get('account_type_id') and not attrs.get('account_type'):
            attrs['account_type'] = resolve_lookup(AccountType, self.initial_data['account_type_id'])
        if not attrs.get('account_type') and self.instance is None:
            attrs['account_type'] = default_lookup(AccountType, 'SAVINGS')
        return attrs


class BankTransactionSerializer(serializers.ModelSerializer):
    transaction_type = LookupField(TransactionType, read_only=True)

    class Meta:
        model = BankTransaction
        fields = ['id', 'account', 'transaction_type', 'amount', 'counter_id', 'timestamp']


class BankCardSerializer(serializers.ModelSerializer):
    card_type = LookupField(CardType, required=False)
    card_type_id = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = BankCard
        fields = [
            'id', 'account', 'card_number', 'card_type', 'card_type_id',
            'is_blocked', 'block_reason',
        ]

    def validate(self, attrs):
        if self.initial_data.get('card_type_id') and not attrs.get('card_type'):
            attrs['card_type'] = resolve_lookup(CardType, self.initial_data['card_type_id'])
        if not attrs.get('card_type') and self.instance is None:
            attrs['card_type'] = default_lookup(CardType, 'VISA_CLASSIC')
        return attrs


class AuditLogSerializer(serializers.ModelSerializer):
    event_type = LookupField(EventType, required=True)
    event_type_id = serializers.IntegerField(write_only=True, required=False)
    severity = LookupField(SeverityLevel, required=False)
    severity_id = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = AuditLog
        fields = ['id', 'event_type', 'event_type_id', 'ip_address', 'severity', 'severity_id', 'timestamp']
        read_only_fields = ['timestamp']

    def validate(self, attrs):
        if self.initial_data.get('event_type_id') and not attrs.get('event_type'):
            attrs['event_type'] = resolve_lookup(EventType, self.initial_data['event_type_id'])
        if self.initial_data.get('severity_id') and not attrs.get('severity'):
            attrs['severity'] = resolve_lookup(SeverityLevel, self.initial_data['severity_id'])
        if not attrs.get('severity'):
            attrs['severity'] = default_lookup(SeverityLevel, 'MEDIUM')
        return attrs
