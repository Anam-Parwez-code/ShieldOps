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
    CyberLogoutView
)

router = DefaultRouter()
router.register(r'vulnerabilities',    VulnerabilityViewSet,         basename='vulnerability')
router.register(r'bank/customers',     CustomerViewSet,              basename='bank-customer')
router.register(r'bank/accounts',      BankAccountViewSet,           basename='bank-account')
router.register(r'bank/transactions',  BankTransactionViewSet,       basename='bank-transaction')
router.register(r'bank/cards',         BankCardViewSet,              basename='bank-card')
router.register(r'bank/audit/logs',    AuditLogViewSet,              basename='audit-log')

urlpatterns = [
    path('admin/', admin.site.urls),

    # ── Auth ──────────────────────────────────────────────────────────────────
    path('api/auth/login/',   TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/refresh/', TokenRefreshView.as_view(),    name='token_refresh'),
    path('api/auth/logout/',  CyberLogoutView.as_view(),     name='token_logout'),

    # ── Admin: Staff ──────────────────────────────────────────────────────────
    path('api/admin/staff/register/', StaffRegistrationViewSet.as_view({'post': 'create'}),    name='staff-register'),
    path('api/admin/staff/',          StaffRegistrationViewSet.as_view({'get': 'list'}),       name='staff-list'),
    
    # FIX DETECTED: Added 'patch' and 'put' mappings to the staff detail path 👇
    path('api/admin/staff/<int:pk>/', StaffRegistrationViewSet.as_view({
        'get': 'retrieve', 
        'patch': 'partial_update', 
        'put': 'update'
    }), name='staff-detail'),

    # ── Admin: Cashiers ───────────────────────────────────────────────────────
    path('api/admin/cashiers/',          CashierViewSet.as_view({'get': 'list', 'post': 'create'}), name='cashier-list'),
    path('api/admin/cashiers/<int:pk>/', CashierViewSet.as_view({
        'get': 'retrieve', 
        'patch': 'partial_update',
        'put': 'update'
    }), name='cashier-detail'),

    # ── Router (all ViewSet routes) ───────────────────────────────────────────
    path('api/', include(router.urls)),
]