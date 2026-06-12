from rest_framework import permissions


def _role_code(user):
    if not user or not user.is_authenticated:
        return None
    if hasattr(user, 'role') and user.role:
        return user.role.code
    return None


class IsSecurityAuditor(permissions.BasePermission):
    """
    Allow read-only safely or restrict write ops to SECURITY_AUDITOR or Superuser.
    """
    def has_permission(self, request, view):
        # View API Check: Agar request GET, HEAD, ya OPTIONS hai toh allow karein
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated

        # Baki destructive actions ke liye purani strict logic
        return request.user.is_authenticated and (
            _role_code(request.user) == 'SECURITY_AUDITOR' or request.user.is_superuser
        )


class IsFinanceManager(permissions.BasePermission):
    """
    Allow read-only safely or restrict write ops to FINANCE_MANAGER, MANAGER, ADMIN or Superuser.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated

        code = _role_code(request.user)
        return request.user.is_authenticated and (
            code in ('FINANCE_MANAGER', 'MANAGER', 'ADMIN') or request.user.is_superuser
        )


class IsOperations(permissions.BasePermission):
    """
    Allow read-only safely or restrict write ops to OPERATIONS, ADMIN or Superuser.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated

        return request.user.is_authenticated and (
            _role_code(request.user) in ('OPERATIONS', 'ADMIN') or request.user.is_superuser
        )


class IsCashier(permissions.BasePermission):
    """
    Allow read-only safely or restrict write ops to CASHIER or Superuser.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated

        return request.user.is_authenticated and (
            _role_code(request.user) == 'CASHIER' or request.user.is_superuser
        )