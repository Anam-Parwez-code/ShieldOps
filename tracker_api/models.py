from django.db import models
from django.contrib.auth.models import AbstractUser

# Custom User with Roles
class User(AbstractUser):
    ROLE_CHOICES = (
        ('ADMIN', 'Admin'),
        ('MANAGER', 'Manager'),
        ('CASHIER', 'Cashier'),
        ('SECURITY_AUDITOR', 'Security Auditor'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='CASHIER')

# Vulnerability Tracker (Audit Tools)
class Vulnerability(models.Model):
    threat_title = models.CharField(max_length=255)
    target_date = models.DateField()
    status = models.CharField(max_length=50, default='CRITICAL')
    completion_date = models.DateField(null=True, blank=True)
    remarks = models.TextField(null=True, blank=True)
    
    # Is field ka naam assigned_auditor se badal kar assigned_to kar diya taaki views se clash na ho
    assigned_to = models.ForeignKey(User, on_delete=models.CASCADE, related_name='threats')
# Core Bank Management Entities
class Customer(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15)
    kyc_status = models.CharField(max_length=20, default='PENDING_VERIFICATION')
    created_at = models.DateTimeField(auto_now_add=True)

class BankAccount(models.Model):
    ACCOUNT_TYPES = (('SAVINGS', 'Savings'), ('CURRENT', 'Current'))
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='accounts')
    account_number = models.CharField(max_length=20, unique=True)
    account_type = models.CharField(max_length=10, choices=ACCOUNT_TYPES, default='SAVINGS')
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    is_active = models.BooleanField(default=True)

class BankTransaction(models.Model):
    account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name='transactions')
    transaction_type = models.CharField(max_length=20) # DEPOSIT, WITHDRAWAL
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    counter_id = models.CharField(max_length=20, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

class BankCard(models.Model):
    account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name='cards')
    card_number = models.CharField(max_length=19, unique=True)
    card_type = models.CharField(max_length=20, default='VISA_PLATINUM')
    is_blocked = models.BooleanField(default=False)
    block_reason = models.CharField(max_length=255, null=True, blank=True)

class AuditLog(models.Model):
    event_type = models.CharField(max_length=50)
    ip_address = models.GenericIPAddressField()
    severity = models.CharField(max_length=10, default='LOW')
    timestamp = models.DateTimeField(auto_now_add=True)