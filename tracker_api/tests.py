from decimal import Decimal

from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from .models import (
    AccountType,
    BankAccount,
    BankCard,
    BankTransaction,
    CardType,
    Customer,
    KycStatus,
    StaffRole,
    TransactionType,
    User,
)


class LookupAndFilterApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin_role = StaffRole.objects.create(code="ADMIN", label="Admin")
        self.manager_role = StaffRole.objects.create(code="MANAGER", label="Manager")
        self.cashier_role = StaffRole.objects.create(code="CASHIER", label="Cashier")
        self.admin = User.objects.create_superuser(
            username="admin",
            email="admin@example.com",
            password="admin-pass-2026",
            role=self.admin_role,
        )
        self.client.force_authenticate(self.admin)

    def test_duplicate_lookup_post_returns_already_exists(self):
        response = self.client.post("/api/admin/roles/", {"role": "manager"}, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "ALREADY_EXISTS")
        self.assertEqual(response.data["role"], "MANAGER")
        self.assertEqual(StaffRole.objects.filter(code="MANAGER").count(), 1)

    def test_staff_role_id_in_filter(self):
        manager = User.objects.create_user(
            username="manager_raj",
            email="manager@example.com",
            password="manager-pass-2026",
            role=self.manager_role,
            is_staff=True,
        )
        User.objects.create_user(
            username="cashier_amit",
            email="cashier@example.com",
            password="cashier-pass-2026",
            role=self.cashier_role,
            is_staff=True,
        )

        response = self.client.get(f"/api/admin/staff/?role_id__in={self.manager_role.id}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual([row["id"] for row in response.data], [manager.id])

    def test_customer_exact_email_and_kyc_filters(self):
        pending = KycStatus.objects.create(code="PENDING", label="Pending")
        approved = KycStatus.objects.create(code="APPROVED", label="Approved")
        customer = Customer.objects.create(
            first_name="Anam",
            last_name="Parwez",
            email="anam.p@shieldops.com",
            phone="9876543210",
            kyc_status=approved,
        )
        Customer.objects.create(
            first_name="Vikram",
            last_name="Singh",
            email="vikram@mail.com",
            phone="9123456789",
            kyc_status=pending,
        )

        response = self.client.get(f"/api/bank/customers/?email=ANAM.P@shieldops.com&kyc_status_id={approved.id}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual([row["id"] for row in response.data], [customer.id])

    def test_card_type_filter(self):
        approved = KycStatus.objects.create(code="APPROVED", label="Approved")
        savings = AccountType.objects.create(code="SAVINGS", label="Savings")
        visa = CardType.objects.create(code="VISA_CLASSIC", label="Visa Classic")
        mastercard = CardType.objects.create(code="MASTERCARD_GOLD", label="Mastercard Gold")
        customer = Customer.objects.create(
            first_name="Anam",
            last_name="Parwez",
            email="anam@example.com",
            phone="9876543210",
            kyc_status=approved,
        )
        account = BankAccount.objects.create(
            customer=customer,
            account_number="SHIELD123456",
            account_type=savings,
            balance=Decimal("5000.00"),
        )
        card = BankCard.objects.create(account=account, card_number="1111-2222-3333-4444", card_type=visa)
        BankCard.objects.create(account=account, card_number="5555-6666-7777-8888", card_type=mastercard)

        response = self.client.get(f"/api/bank/cards/?card_type_id={visa.id}")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual([row["id"] for row in response.data], [card.id])

    def test_transaction_counter_filter_accepts_raw_counter_id(self):
        approved = KycStatus.objects.create(code="APPROVED", label="Approved")
        savings = AccountType.objects.create(code="SAVINGS", label="Savings")
        deposit = TransactionType.objects.create(code="DEPOSIT", label="Deposit")
        withdrawal = TransactionType.objects.create(code="WITHDRAWAL", label="Withdrawal")
        customer = Customer.objects.create(
            first_name="Anam",
            last_name="Parwez",
            email="anam@example.com",
            phone="9876543210",
            kyc_status=approved,
        )
        account = BankAccount.objects.create(
            customer=customer,
            account_number="SHIELD123456",
            account_type=savings,
            balance=Decimal("5000.00"),
        )
        txn = BankTransaction.objects.create(
            account=account,
            transaction_type=deposit,
            amount=Decimal("100.00"),
            counter_id="CTR_5",
        )
        BankTransaction.objects.create(account=account, transaction_type=withdrawal, amount=Decimal("50.00"))

        response = self.client.get(f"/api/bank/transactions/?transaction_type_id={deposit.id}&counter_id=5")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual([row["id"] for row in response.data], [txn.id])
