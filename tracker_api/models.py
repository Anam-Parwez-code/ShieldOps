from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


class BaseLookup(models.Model):
    code = models.CharField(max_length=50, unique=True)
    label = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)

    class Meta:
        abstract = True
        ordering = ["id"]

    def __str__(self):
        return self.label


class StaffRole(BaseLookup):
    pass


class AccountType(BaseLookup):
    pass


class KycStatus(BaseLookup):
    pass


class ThreatStatus(BaseLookup):
    pass


class SeverityLevel(BaseLookup):
    pass


class CardType(BaseLookup):
    pass


class EventType(BaseLookup):
    pass


class TransactionType(BaseLookup):
    pass


class CardBlockReason(BaseLookup):
    pass


class TransferType(BaseLookup):
    pass


class LoanType(BaseLookup):
    pass


class Counter(BaseLookup):
    pass


class LoanStatus(BaseLookup):
    pass


class LoanDecision(BaseLookup):
    pass


class CommunicationType(BaseLookup):
    pass


class NotificationStatus(BaseLookup):
    pass


class User(AbstractUser):
    email = models.EmailField(unique=True)
    role = models.ForeignKey(
        StaffRole,
        on_delete=models.PROTECT,
        related_name="users",
        null=True,
        blank=True,
    )


class Vulnerability(models.Model):
    threat_title = models.CharField(max_length=255)
    target_date = models.DateField()
    status = models.ForeignKey(ThreatStatus, on_delete=models.PROTECT, related_name="vulnerabilities")
    severity = models.ForeignKey(
        SeverityLevel,
        on_delete=models.PROTECT,
        related_name="vulnerabilities",
        null=True,
        blank=True,
    )
    completion_date = models.DateField(null=True, blank=True)
    remarks = models.TextField(null=True, blank=True)
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="threats")


class Customer(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15)
    kyc_status = models.ForeignKey(KycStatus, on_delete=models.PROTECT, related_name="customers")
    created_at = models.DateTimeField(auto_now_add=True)


class BankAccount(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name="accounts")
    account_number = models.CharField(max_length=20, unique=True)
    account_type = models.ForeignKey(AccountType, on_delete=models.PROTECT, related_name="accounts")
    balance = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    is_active = models.BooleanField(default=True)


class BankTransaction(models.Model):
    account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name="transactions")
    transaction_type = models.ForeignKey(TransactionType, on_delete=models.PROTECT, related_name="transactions")
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    counter_id = models.CharField(max_length=20, null=True, blank=True)
    reference_no = models.CharField(max_length=40, blank=True)
    related_account = models.ForeignKey(
        BankAccount,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="related_transactions",
    )
    timestamp = models.DateTimeField(auto_now_add=True)


class BankCard(models.Model):
    account = models.ForeignKey(BankAccount, on_delete=models.CASCADE, related_name="cards")
    card_number = models.CharField(max_length=19, unique=True)
    card_type = models.ForeignKey(CardType, on_delete=models.PROTECT, related_name="cards")
    is_blocked = models.BooleanField(default=False)
    block_reason = models.ForeignKey(
        CardBlockReason,
        on_delete=models.PROTECT,
        related_name="cards",
        null=True,
        blank=True,
    )
    issued_at = models.DateTimeField(auto_now_add=True)


class AuditLog(models.Model):
    event_type = models.ForeignKey(EventType, on_delete=models.PROTECT, related_name="audit_logs")
    ip_address = models.GenericIPAddressField(default="127.0.0.1")
    severity = models.ForeignKey(SeverityLevel, on_delete=models.PROTECT, related_name="audit_logs")
    timestamp = models.DateTimeField(auto_now_add=True)


class Loan(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name="loans")
    loan_type = models.ForeignKey(LoanType, on_delete=models.PROTECT, related_name="loans")
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    tenure_months = models.PositiveIntegerField()
    status = models.ForeignKey(LoanStatus, on_delete=models.PROTECT, related_name="loans")
    interest_rate = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="approved_loans",
        null=True,
        blank=True,
    )
    disbursed_to_account = models.ForeignKey(
        BankAccount,
        on_delete=models.SET_NULL,
        related_name="loan_disbursements",
        null=True,
        blank=True,
    )
    transaction_reference = models.CharField(max_length=40, blank=True)
    applied_at = models.DateTimeField(auto_now_add=True)


class NotificationLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications")
    communication_type = models.ForeignKey(CommunicationType, on_delete=models.PROTECT, related_name="notifications")
    message = models.TextField()
    status = models.ForeignKey(NotificationStatus, on_delete=models.PROTECT, related_name="notifications")
    sent_at = models.DateTimeField(auto_now_add=True)
