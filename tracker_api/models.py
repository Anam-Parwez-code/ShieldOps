from django.db import models
from django.contrib.auth.models import AbstractUser


# ── Lookup / Reference Tables (ID-based access) ──────────────────────────────

class StaffRole(models.Model):
    code = models.CharField(max_length=30, unique=True)
    label = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.label


class AccountType(models.Model):
    code = models.CharField(max_length=30, unique=True)
    label = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.label


class KycStatus(models.Model):
    code = models.CharField(max_length=30, unique=True)
    label = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.label


class ThreatStatus(models.Model):
    code = models.CharField(max_length=30, unique=True)
    label = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.label


class SeverityLevel(models.Model):
    code = models.CharField(max_length=20, unique=True)
    label = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.label


class CardType(models.Model):
    code = models.CharField(max_length=30, unique=True)
    label = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.label


class EventType(models.Model):
    code = models.CharField(max_length=50, unique=True)
    label = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.label


class TransactionType(models.Model):
    code = models.CharField(max_length=20, unique=True)
    label = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.label


# ── Custom User with Role FK ─────────────────────────────────────────────────

class User(AbstractUser):
    role = models.ForeignKey(
        StaffRole,
        on_delete=models.PROTECT,
        related_name='users',
        null=True,
        blank=True,
    )


# ── Vulnerability Tracker ────────────────────────────────────────────────────

class Vulnerability(models.Model):
    threat_title = models.CharField(max_length=255)
    target_date = models.DateField()
    status = models.ForeignKey(
        ThreatStatus,
        on_delete=models.PROTECT,
        related_name='vulnerabilities',
    )
    severity = models.ForeignKey(
        SeverityLevel,
        on_delete=models.PROTECT,
        related_name='vulnerabilities',
        null=True,
        blank=True,
    )
    completion_date = models.DateField(null=True, blank=True)
    remarks = models.TextField(null=True, blank=True)
    assigned_to = models.ForeignKey(User, on_delete=models.CASCADE, related_name='threats')


# ── Core Bank Management ─────────────────────────────────────────────────────

class Customer(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15)
    kyc_status = models.ForeignKey(
        KycStatus,
        on_delete=models.PROTECT,
        related_name='customers',
    )
    created_at = models.DateTimeField(auto_now_add=True)


class BankAccount(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='accounts')
    account_number = models.CharField(max_length=20, unique=True)
    account_type = models.ForeignKey(
        AccountType,
        on_delete=models.PROTECT,
        related_name='accounts',
    )
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0.00)
    is_active = models.BooleanField(default=True)


class BankTransaction(models.Model):
    account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name='transactions')
    transaction_type = models.ForeignKey(
        TransactionType,
        on_delete=models.PROTECT,
        related_name='transactions',
    )
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    counter_id = models.CharField(max_length=20, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)


class BankCard(models.Model):
    account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name='cards')
    card_number = models.CharField(max_length=19, unique=True)
    card_type = models.ForeignKey(
        CardType,
        on_delete=models.PROTECT,
        related_name='cards',
    )
    is_blocked = models.BooleanField(default=False)
    block_reason = models.CharField(max_length=255, null=True, blank=True)


class AuditLog(models.Model):
    event_type = models.ForeignKey(
        EventType,
        on_delete=models.PROTECT,
        related_name='audit_logs',
    )
    ip_address = models.GenericIPAddressField()
    severity = models.ForeignKey(
        SeverityLevel,
        on_delete=models.PROTECT,
        related_name='audit_logs',
    )
    timestamp = models.DateTimeField(auto_now_add=True)
