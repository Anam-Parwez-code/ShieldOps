from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

class CyberVulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical Risk'),
        ('HIGH', 'High Risk'),
        ('MEDIUM', 'Medium Risk'),
        ('PATCHED_SECURED', 'Patched & Secured'),
    ]
    
    # Runtime compliance evaluation
    if getattr(settings, 'GULF_MODE', False):
        COMPLIANCE_STANDARDS = [
            ('KSA_NCA_2026', 'KSA National Cybersecurity Authority Compliance'),
            ('UAE_NESA', 'UAE National Electronic Security Authority Policy'),
        ]
    else:
        COMPLIANCE_STANDARDS = [
            ('ISO_27001', 'ISO/IEC 27001 Global Information Security Standard'),
            ('SOC_2', 'SOC 2 Corporate Operational Trust Principles'),
        ]

    assigned_to = models.ForeignKey(User, on_delete=models.CASCADE, related_name='vulnerabilities')
    
    # Tracking Attributes
    threat_title = models.CharField(max_length=255)
    compliance_framework = models.CharField(max_length=30, choices=COMPLIANCE_STANDARDS)
    description = models.TextField()
    
   
    target_date = models.DateField(help_text="Mandatory fixing deadline (SLA)")
    completion_date = models.DateField(blank=True, null=True, help_text="Actual patch deployment timeline")
    status = models.CharField(max_length=30, choices=SEVERITY_CHOICES, default='CRITICAL')
    remarks = models.TextField(blank=True, null=True, help_text="Audit and patch deployment log notes")
    
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.threat_title} - {self.status}"