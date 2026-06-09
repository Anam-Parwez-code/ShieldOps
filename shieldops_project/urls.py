from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from tracker_api.views import (
    VulnerabilityViewSet,
    CustomerViewSet,
    BankAccountViewSet,
    BankTransactionViewSet,
    BankCardViewSet,
    AuditLogViewSet,
    StaffRegistrationViewSet,
    CashierViewSet,
    CyberLogoutView,
    AccountTypesChoiceView,
    CardTypesChoiceView,
    KycStatusesChoiceView,
    ThreatStatusesChoiceView,
    SeverityLevelsChoiceView,
    EventTypesChoiceView,
    StaffRolesChoiceView,
    AdminDashboardSummaryView,
)

router = DefaultRouter()
router.register(r'vulnerabilities', VulnerabilityViewSet, basename='vulnerability')
router.register(r'bank/customers', CustomerViewSet, basename='bank-customer')
router.register(r'bank/accounts', BankAccountViewSet, basename='bank-account')
router.register(r'bank/transactions', BankTransactionViewSet, basename='bank-transaction')
router.register(r'bank/cards', BankCardViewSet, basename='bank-card')
router.register(r'bank/audit/logs', AuditLogViewSet, basename='audit-log')

urlpatterns = [
    path('admin/', admin.site.urls),

    # Auth
    path('api/auth/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/logout/', CyberLogoutView.as_view(), name='token_logout'),

    # Admin
    path('api/admin/staff/register/', StaffRegistrationViewSet.as_view({'post': 'create'}), name='staff-register'),
    path('api/admin/staff/', StaffRegistrationViewSet.as_view({'get': 'list'}), name='staff-list'),
    path('api/admin/staff/<int:pk>/', StaffRegistrationViewSet.as_view({
        'get': 'retrieve', 'patch': 'partial_update', 'put': 'update',
    }), name='staff-detail'),
    path('api/admin/cashiers/', CashierViewSet.as_view({'get': 'list', 'post': 'create'}), name='cashier-list'),
    path('api/admin/cashiers/<int:pk>/', CashierViewSet.as_view({
        'get': 'retrieve', 'patch': 'partial_update', 'put': 'update',
    }), name='cashier-detail'),
    path('api/admin/roles/', StaffRolesChoiceView.as_view(), name='staff-roles'),
    path('api/admin/dashboard/summary/', AdminDashboardSummaryView.as_view(), name='admin-dashboard'),

    # Choice lookups (ID-based)
    path('api/choices/account-types/', AccountTypesChoiceView.as_view(), name='choice-account-types'),
    path('api/choices/card-types/', CardTypesChoiceView.as_view(), name='choice-card-types'),
    path('api/choices/kyc-statuses/', KycStatusesChoiceView.as_view(), name='choice-kyc-statuses'),
    path('api/choices/threat-statuses/', ThreatStatusesChoiceView.as_view(), name='choice-threat-statuses'),
    path('api/choices/severity-levels/', SeverityLevelsChoiceView.as_view(), name='choice-severity-levels'),
    path('api/choices/event-types/', EventTypesChoiceView.as_view(), name='choice-event-types'),

    path('api/', include(router.urls)),
]
