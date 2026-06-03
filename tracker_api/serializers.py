from rest_framework import serializers
from .models import CyberVulnerability

class CyberVulnerabilitySerializer(serializers.ModelSerializer):
    assigned_username = serializers.ReadOnlyField(source='assigned_to.username')

    class Meta:
        model = CyberVulnerability
        fields = [
            'id', 'assigned_username', 'threat_title', 'compliance_framework', 
            'description', 'target_date', 'completion_date', 'status', 'remarks', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']

    def create(self, validated_data):
        validated_data['assigned_to'] = self.context['request'].user
        return super().create(validated_data)