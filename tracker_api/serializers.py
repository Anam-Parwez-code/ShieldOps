from rest_framework import serializers
from .models import User, Vulnerability, Customer, BankAccount, BankTransaction, BankCard, AuditLog

class CyberVulnerabilitySerializer(serializers.ModelSerializer):
    # Agar user model me reference field ka naam 'assigned_to' hai toh:
    assigned_username = serializers.ReadOnlyField(source='assigned_to.username')

    class Meta:
        model = Vulnerability  # <--- Yeh change kar diya (Naya model name mapped)
        fields = [
            'id', 'assigned_username', 'threat_title', 
            'target_date', 'completion_date', 'status', 'remarks'
        ]
        read_only_fields = ['id']

    def create(self, validated_data):
        # Request user ko automatically link karne ke liye
        validated_data['assigned_to'] = self.context['request'].user
        return super().create(validated_data)

# --- Banking Serializers ---

class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = '__all__'


class BankAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankAccount
        fields = '__all__'


class BankTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankTransaction
        fields = '__all__'

class BankCardSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankCard
        fields = '__all__'

class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = '__all__'