from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password

from tracker_api.models import (
    StaffRole, AccountType, KycStatus, ThreatStatus, SeverityLevel,
    CardType, EventType, TransactionType, User,
)


LOOKUPS = {
    StaffRole: [
        ('ADMIN', 'Super Admin'),
        ('FINANCE_MANAGER', 'Finance Manager'),
        ('OPERATIONS', 'Operations Staff'),
        ('CASHIER', 'Cashier'),
        ('SECURITY_AUDITOR', 'Security Auditor'),
    ],
    AccountType: [
        ('SAVINGS', 'Savings Account'),
        ('CURRENT', 'Current Account'),
        ('FIXED_DEPOSIT', 'Fixed Deposit'),
    ],
    KycStatus: [
        ('PENDING_VERIFICATION', 'Pending Verification'),
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
    ],
    ThreatStatus: [
        ('CRITICAL', 'Critical'),
        ('PATCHED_SECURED', 'Patched & Secured'),
        ('UNDER_REVIEW', 'Under Review'),
    ],
    SeverityLevel: [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ],
    CardType: [
        ('VISA_PLATINUM', 'Visa Platinum'),
        ('VISA_CLASSIC', 'Visa Classic'),
        ('MASTERCARD_GOLD', 'Mastercard Gold'),
    ],
    EventType: [
        ('BRUTE_FORCE_ATTEMPT', 'Brute Force Attempt'),
        ('PARAMETER_TAMPERING', 'Parameter Tampering'),
        ('MALICIOUS_BALANCE_INJECTION', 'Malicious Balance Injection'),
        ('UNAUTHORIZED_ACCESS', 'Unauthorized Access'),
    ],
    TransactionType: [
        ('DEPOSIT', 'Deposit'),
        ('WITHDRAWAL', 'Withdrawal'),
    ],
}


class Command(BaseCommand):
    help = 'Seed lookup tables and create default superuser'

    def handle(self, *args, **options):
        for model, rows in LOOKUPS.items():
            for code, label in rows:
                model.objects.update_or_create(code=code, defaults={'label': label, 'is_active': True})
            self.stdout.write(self.style.SUCCESS(f'Seeded {model.__name__}: {len(rows)} records'))

        admin_role = StaffRole.objects.get(code='ADMIN')
        if not User.objects.filter(username='admin').exists():
            User.objects.create(
                username='admin',
                email='admin@shieldops.com',
                password=make_password('admin123'),
                is_superuser=True,
                is_staff=True,
                is_active=True,
                role=admin_role,
            )
            self.stdout.write(self.style.SUCCESS('Created superuser: admin / admin123'))

        self.stdout.write(self.style.SUCCESS('Lookup seed complete.'))
