from rest_framework import permissions


def _role_code(user):
    if not user or not user.is_authenticated:
        return None
    if hasattr(user, 'role') and user.role:
        return user.role.code
    return None


class IsSecurityAuditor(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            _role_code(request.user) == 'SECURITY_AUDITOR' or request.user.is_superuser
        )


class IsFinanceManager(permissions.BasePermission):
    def has_permission(self, request, view):
        code = _role_code(request.user)
        return request.user.is_authenticated and (
            code in ('FINANCE_MANAGER', 'MANAGER', 'ADMIN') or request.user.is_superuser
        )


class IsOperations(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            _role_code(request.user) in ('OPERATIONS', 'ADMIN') or request.user.is_superuser
        )


class IsCashier(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            _role_code(request.user) == 'CASHIER' or request.user.is_superuser
        )
