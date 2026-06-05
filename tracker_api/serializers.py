from rest_framework import serializers
from .models import User, Vulnerability, Customer, BankAccount, BankTransaction, BankCard, AuditLog


# ── User / Staff Serializer ───────────────────────────────────────────────────
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'is_active', 'is_staff', 'date_joined']
        read_only_fields = ['id', 'date_joined']


# ── Vulnerability ─────────────────────────────────────────────────────────────
class CyberVulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = '__all__'


# ── Customer ──────────────────────────────────────────────────────────────────
class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = '__all__'


# ── Bank Account ──────────────────────────────────────────────────────────────
class BankAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankAccount
        fields = '__all__'


# ── Bank Transaction ──────────────────────────────────────────────────────────
class BankTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankTransaction
        fields = '__all__'


# ── Bank Card ─────────────────────────────────────────────────────────────────
class BankCardSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankCard
        fields = '__all__'


# ── Audit Log ─────────────────────────────────────────────────────────────────
class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = '__all__'