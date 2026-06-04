from rest_framework import permissions

class IsSecurityAuditor(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            getattr(request.user, 'role', '') == 'SECURITY_AUDITOR' or request.user.is_superuser
        )

class IsManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            getattr(request.user, 'role', '') == 'MANAGER' or request.user.is_superuser
        )

class IsCashier(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            getattr(request.user, 'role', '') == 'CASHIER' or request.user.is_superuser
        )