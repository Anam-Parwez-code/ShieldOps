from django.contrib import admin
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from tracker_api.views import (
    ActiveSessionsListView,
    AdminDashboardSummaryView,
    AuditLogViewSet,
    BankAccountViewSet,
    BankCardViewSet,
    BankTransactionViewSet,
    CyberLogoutView,
    CustomerViewSet,
    ForceLogoutSessionView,
    LoanViewSet,
    LookupChoiceView,
    NotificationViewSet,
    OtpGenerationView,
    PasswordChangeView,
    StaffRegistrationViewSet,
    StaffRolesChoiceView,
    VulnerabilityViewSet,
)


router = DefaultRouter()
router.register(r"vulnerabilities", VulnerabilityViewSet, basename="vulnerability")
router.register(r"bank/customers", CustomerViewSet, basename="bank-customer")
router.register(r"bank/accounts", BankAccountViewSet, basename="bank-account")
router.register(r"bank/transactions", BankTransactionViewSet, basename="bank-transaction")
router.register(r"bank/cards", BankCardViewSet, basename="bank-card")
router.register(r"bank/audit/logs", AuditLogViewSet, basename="audit-log")
router.register(r"bank/loans", LoanViewSet, basename="bank-loan")
router.register(r"bank/notifications", NotificationViewSet, basename="bank-notification")

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/auth/login/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/auth/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/auth/logout/", CyberLogoutView.as_view(), name="token_logout"),
    path("api/auth/password/change/", PasswordChangeView.as_view(), name="password-change"),
    path("api/auth/sessions/", ActiveSessionsListView.as_view(), name="active-sessions"),
    path("api/auth/sessions/<str:session_id>/revoke/", ForceLogoutSessionView.as_view(), name="session-revoke"),
    path("api/auth/otp/generate/", OtpGenerationView.as_view(), name="otp-generate"),
    path("api/admin/staff/register/", StaffRegistrationViewSet.as_view({"post": "create"}), name="staff-register"),
    path("api/admin/staff/", StaffRegistrationViewSet.as_view({"get": "list"}), name="staff-list"),
    path(
        "api/admin/staff/<int:pk>/",
        StaffRegistrationViewSet.as_view({"get": "retrieve", "patch": "partial_update", "put": "partial_update"}),
        name="staff-detail",
    ),
    path("api/admin/roles/", StaffRolesChoiceView.as_view(), name="staff-roles"),
    path("api/admin/dashboard/summary/", AdminDashboardSummaryView.as_view(), name="admin-dashboard"),
    path("api/choices/<str:slug>/", LookupChoiceView.as_view(), name="choice-lookup"),
    path("api/", include(router.urls)),
]
