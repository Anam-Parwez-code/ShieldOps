from django.contrib.auth.hashers import make_password
from django.core.management.base import BaseCommand

from tracker_api.models import (
    AccountType,
    CardBlockReason,
    CardType,
    CommunicationType,
    Counter,
    EventType,
    KycStatus,
    LoanDecision,
    LoanStatus,
    LoanType,
    NotificationStatus,
    SeverityLevel,
    StaffRole,
    ThreatStatus,
    TransactionType,
    TransferType,
    User,
)


LOOKUPS = {
    StaffRole: [("ADMIN", "Super Admin", False), ("MANAGER", "Manager", False), ("CASHIER", "Cashier", True), ("SECURITY_AUDITOR", "Security Auditor", False)],
    AccountType: [("SAVINGS", "Savings", True), ("CURRENT", "Current", False), ("FIXED_DEPOSIT", "Fixed Deposit", False)],
    KycStatus: [("PENDING", "Pending", True), ("APPROVED", "Approved", False), ("REJECTED", "Rejected", False)],
    ThreatStatus: [("CRITICAL", "Critical", True), ("PATCHED_SECURED", "Patched Secured", False), ("UNDER_REVIEW", "Under Review", False)],
    SeverityLevel: [("LOW", "Low", False), ("MEDIUM", "Medium", True), ("HIGH", "High", False), ("CRITICAL", "Critical", False)],
    CardType: [("VISA_PLATINUM", "Visa Platinum", False), ("VISA_CLASSIC", "Visa Classic", True), ("MASTERCARD_GOLD", "Mastercard Gold", False)],
    CardBlockReason: [("LOST", "Lost", False), ("STOLEN", "Stolen", False), ("FRAUD_SUSPECTED", "Fraud Suspected", False)],
    EventType: [("BRUTE_FORCE_ATTEMPT", "Brute Force Attempt", False), ("PARAMETER_TAMPERING", "Parameter Tampering", False), ("MALICIOUS_BALANCE_INJECTION", "Malicious Balance Injection", False)],
    TransactionType: [("DEPOSIT", "Deposit", False), ("WITHDRAWAL", "Withdrawal", False), ("TRANSFER", "Transfer", False)],
    TransferType: [("IMPS", "IMPS", True), ("NEFT", "NEFT", False), ("RTGS", "RTGS", False)],
    LoanType: [("PERSONAL_LOAN", "Personal Loan", False), ("HOME_LOAN", "Home Loan", False), ("CAR_LOAN", "Car Loan", False)],
    Counter: [("COUNTER_01", "Counter 01", False), ("COUNTER_02", "Counter 02", False)],
    LoanStatus: [("PENDING", "Pending", True), ("APPROVED", "Approved", False), ("REJECTED", "Rejected", False)],
    LoanDecision: [("REJECT", "Reject", False), ("APPROVE", "Approve", False)],
    CommunicationType: [("OTP", "OTP", False), ("EMAIL", "Email", False), ("SMS", "SMS", False)],
    NotificationStatus: [("PENDING", "Pending", False), ("SENT", "Sent", True), ("FAILED", "Failed", False)],
}


class Command(BaseCommand):
    help = "Seed lookup tables and create a default superuser"

    def handle(self, *args, **options):
        for model, rows in LOOKUPS.items():
            for code, label, is_default in rows:
                model.objects.update_or_create(
                    code=code,
                    defaults={"label": label, "is_active": True, "is_default": is_default},
                )
            self.stdout.write(self.style.SUCCESS(f"Seeded {model.__name__}: {len(rows)} records"))

        admin_role = StaffRole.objects.get(code="ADMIN")
        User.objects.update_or_create(
            username="admin",
            defaults={
                "email": "admin@shieldops.com",
                "password": make_password("admin123"),
                "is_superuser": True,
                "is_staff": True,
                "is_active": True,
                "role": admin_role,
            },
        )
        self.stdout.write(self.style.SUCCESS("Default superuser ready: admin / admin123"))
