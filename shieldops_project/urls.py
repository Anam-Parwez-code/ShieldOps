from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

# Pure naming integrations fixed here
from tracker_api.views import (
    VulnerabilityViewSet, 
    CustomerViewSet, 
    BankAccountViewSet, 
    BankTransactionViewSet,  # Fixed from TransactionViewSet
    BankCardViewSet, 
    AuditLogViewSet, 
    StaffRegistrationViewSet,
    CyberLogoutView           # Imported explicitly
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
    
    # Auth Layout Enforcements
    path('api/auth/login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/logout/', CyberLogoutView.as_view(), name='token_logout'),
    
    # Core Admin App Registration Endpoints
    path('api/admin/staff/register/', StaffRegistrationViewSet.as_view({'post': 'create'})),
    
    path('api/', include(router.urls)),
]