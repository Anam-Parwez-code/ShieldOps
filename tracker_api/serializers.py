from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import User, Vulnerability, Customer, BankAccount, BankTransaction, BankCard, AuditLog

# ── User / Staff Serializer ───────────────────────────────────────────────────
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'is_active', 'is_staff', 'date_joined', 'password', 'confirm_password']
        read_only_fields = ['id', 'date_joined']

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password and Confirm Password do not match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        raw_password = validated_data.pop('password')
        validated_data['password'] = make_password(raw_password)
        
        # Initial workflow states mapped from sheet
        validated_data['is_active'] = False
        validated_data['is_staff'] = True
        return super().create(validated_data)


# ── Vulnerability Serializer ──────────────────────────────────────────────────
class CyberVulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = '__all__'


# ── Customer Serializer ───────────────────────────────────────────────────────
class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = '__all__'


# ── Bank Account Serializer ────────────────────────────────────────────────────
class BankAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankAccount
        fields = '__all__'


# ── Bank Transaction Serializer ────────────────────────────────────────────────
class BankTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankTransaction
        fields = '__all__'


# ── Bank Card Serializer ───────────────────────────────────────────────────────
class BankCardSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankCard
        fields = '__all__'


# ── Audit Log Serializer ───────────────────────────────────────────────────────
class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = '__all__'