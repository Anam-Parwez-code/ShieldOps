from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from .lookups import default_lookup
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


def lookup_payload(obj, key):
    if obj is None:
        return None
    return {"id": obj.id, key: obj.code, "label": obj.label, "is_default": obj.is_default}


class UserSerializer(serializers.ModelSerializer):
    role_id = serializers.PrimaryKeyRelatedField(source="role", queryset=StaffRole.objects.all(), write_only=True)
    role = serializers.SerializerMethodField(read_only=True)
    status = serializers.SerializerMethodField(read_only=True)
    password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "role",
            "role_id",
            "password",
            "confirm_password",
            "is_active",
            "is_staff",
            "date_joined",
            "status",
        ]
        read_only_fields = ["id", "role", "is_staff", "date_joined", "status"]

    def get_role(self, obj):
        return obj.role.id if obj.role else None

    def get_status(self, obj):
        return "APPROVED" if obj.is_active else "PENDING_APPROVAL"

    def validate(self, attrs):
        password = attrs.get("password")
        confirm = attrs.pop("confirm_password", None)
        if password or confirm:
            if password != confirm:
                raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
            validate_password(password)
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        user = User(**validated_data)
        user.is_staff = True
        user.is_active = False
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save()
        return user


class CyberVulnerabilitySerializer(serializers.ModelSerializer):
    status_id = serializers.PrimaryKeyRelatedField(source="status", queryset=ThreatStatus.objects.all(), write_only=True)
    severity_id = serializers.PrimaryKeyRelatedField(
        source="severity", queryset=SeverityLevel.objects.all(), write_only=True, required=False, allow_null=True
    )
    status = serializers.SerializerMethodField(read_only=True)
    severity = serializers.SerializerMethodField(read_only=True)
    assigned_to = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Vulnerability
        fields = [
            "id",
            "threat_title",
            "target_date",
            "status",
            "status_id",
            "severity",
            "severity_id",
            "completion_date",
            "remarks",
            "assigned_to",
        ]

    def get_status(self, obj):
        return obj.status.code if obj.status else None

    def get_severity(self, obj):
        return obj.severity.id if obj.severity else None


class CustomerSerializer(serializers.ModelSerializer):
    kyc_status_id = serializers.PrimaryKeyRelatedField(
        source="kyc_status", queryset=KycStatus.objects.all(), write_only=True, required=False
    )
    kyc_status = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Customer
        fields = ["id", "first_name", "last_name", "email", "phone", "kyc_status", "kyc_status_id", "created_at"]
        read_only_fields = ["id", "kyc_status", "created_at"]

    def get_kyc_status(self, obj):
        return obj.kyc_status.id if obj.kyc_status else None

    def create(self, validated_data):
        if "kyc_status" not in validated_data:
            validated_data["kyc_status"] = default_lookup(KycStatus, "PENDING") or default_lookup(KycStatus, "PENDING_VERIFICATION")
        return super().create(validated_data)


class BankAccountSerializer(serializers.ModelSerializer):
    customer_id = serializers.PrimaryKeyRelatedField(source="customer", queryset=Customer.objects.all(), write_only=True)
    account_type_id = serializers.PrimaryKeyRelatedField(
        source="account_type", queryset=AccountType.objects.all(), write_only=True, required=False
    )
    customer = serializers.PrimaryKeyRelatedField(read_only=True)
    account_type = serializers.SerializerMethodField(read_only=True)
    account_number = serializers.CharField(read_only=True)

    class Meta:
        model = BankAccount
        fields = [
            "id",
            "customer",
            "customer_id",
            "account_number",
            "account_type",
            "account_type_id",
            "balance",
            "is_active",
        ]
        read_only_fields = ["id", "customer", "account_number", "account_type"]

    def get_account_type(self, obj):
        return obj.account_type.id if obj.account_type else None

    def create(self, validated_data):
        if "account_type" not in validated_data:
            validated_data["account_type"] = default_lookup(AccountType, "SAVINGS")
        return super().create(validated_data)


class BankTransactionSerializer(serializers.ModelSerializer):
    transaction_type_id = serializers.PrimaryKeyRelatedField(
        source="transaction_type", queryset=TransactionType.objects.all(), write_only=True, required=False
    )
    transaction_type = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = BankTransaction
        fields = [
            "id",
            "account",
            "transaction_type",
            "transaction_type_id",
            "amount",
            "counter_id",
            "reference_no",
            "related_account",
            "timestamp",
        ]
        read_only_fields = ["id", "transaction_type", "timestamp"]

    def get_transaction_type(self, obj):
        return obj.transaction_type.code if obj.transaction_type else None


class BankCardSerializer(serializers.ModelSerializer):
    account_id = serializers.PrimaryKeyRelatedField(source="account", queryset=BankAccount.objects.all(), write_only=True)
    card_type_id = serializers.PrimaryKeyRelatedField(source="card_type", queryset=CardType.objects.all(), write_only=True)
    block_reason_id = serializers.PrimaryKeyRelatedField(
        source="block_reason", queryset=CardBlockReason.objects.all(), write_only=True, required=False, allow_null=True
    )
    account = serializers.PrimaryKeyRelatedField(read_only=True)
    card_type = serializers.SerializerMethodField(read_only=True)
    block_reason = serializers.SerializerMethodField(read_only=True)
    card_number = serializers.CharField(read_only=True)

    class Meta:
        model = BankCard
        fields = [
            "id",
            "account",
            "account_id",
            "card_number",
            "card_type",
            "card_type_id",
            "is_blocked",
            "block_reason",
            "block_reason_id",
            "issued_at",
        ]
        read_only_fields = ["id", "account", "card_number", "card_type", "block_reason", "issued_at"]

    def get_card_type(self, obj):
        return obj.card_type.code if obj.card_type else None

    def get_block_reason(self, obj):
        return obj.block_reason.code if obj.block_reason else None


class AuditLogSerializer(serializers.ModelSerializer):
    event_type_id = serializers.PrimaryKeyRelatedField(source="event_type", queryset=EventType.objects.all(), write_only=True)
    severity_id = serializers.PrimaryKeyRelatedField(source="severity", queryset=SeverityLevel.objects.all(), write_only=True)
    event_type = serializers.SerializerMethodField(read_only=True)
    severity = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = AuditLog
        fields = ["id", "event_type", "event_type_id", "ip_address", "severity", "severity_id", "timestamp"]
        read_only_fields = ["id", "event_type", "severity", "timestamp"]

    def get_event_type(self, obj):
        return obj.event_type.code if obj.event_type else None

    def get_severity(self, obj):
        return obj.severity.code if obj.severity else None


class LoanSerializer(serializers.ModelSerializer):
    customer_id = serializers.PrimaryKeyRelatedField(source="customer", queryset=Customer.objects.all(), write_only=True)
    loan_type_id = serializers.PrimaryKeyRelatedField(source="loan_type", queryset=LoanType.objects.all(), write_only=True)
    customer = serializers.PrimaryKeyRelatedField(read_only=True)
    loan_type = serializers.SerializerMethodField(read_only=True)
    status_id = serializers.IntegerField(read_only=True)
    loan_id = serializers.IntegerField(source="id", read_only=True)

    class Meta:
        model = Loan
        fields = [
            "loan_id",
            "id",
            "customer",
            "customer_id",
            "loan_type",
            "loan_type_id",
            "amount",
            "tenure_months",
            "status_id",
            "interest_rate",
            "approved_by",
            "disbursed_to_account",
            "transaction_reference",
            "applied_at",
        ]
        read_only_fields = [
            "loan_id",
            "id",
            "customer",
            "loan_type",
            "status_id",
            "interest_rate",
            "approved_by",
            "disbursed_to_account",
            "transaction_reference",
            "applied_at",
        ]

    def get_loan_type(self, obj):
        return obj.loan_type.id if obj.loan_type else None

    def create(self, validated_data):
        validated_data["status"] = default_lookup(LoanStatus, "PENDING")
        return super().create(validated_data)


class NotificationSerializer(serializers.ModelSerializer):
    user_id = serializers.PrimaryKeyRelatedField(source="user", queryset=User.objects.all(), write_only=True, required=False)
    communication_type_id = serializers.PrimaryKeyRelatedField(
        source="communication_type", queryset=CommunicationType.objects.all(), write_only=True
    )
    status_id = serializers.PrimaryKeyRelatedField(
        source="status", queryset=NotificationStatus.objects.all(), write_only=True, required=False
    )
    user = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = NotificationLog
        fields = ["id", "user", "user_id", "communication_type_id", "message", "sent_at", "status_id"]
        read_only_fields = ["id", "user", "sent_at"]

    def create(self, validated_data):
        request = self.context.get("request")
        if "user" not in validated_data and request:
            validated_data["user"] = request.user
        if "status" not in validated_data:
            validated_data["status"] = default_lookup(NotificationStatus, "SENT")
        return super().create(validated_data)
