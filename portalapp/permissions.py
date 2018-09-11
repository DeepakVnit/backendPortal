from django.contrib import admin
from rest_framework.exceptions import PermissionDenied

class ModelObjectPermission(admin.ModelAdmin):
    def has_change_permission(self, request, user=None):
        if request.user.is_superuser:
            return True
        if user.email == request.user.email:
            return True
        raise PermissionDenied

    def has_delete_permission(self, request, user=None):
        if request.user.is_superuser:
            return True
        if user.email == request.user.email:
            return True
        raise PermissionDenied

    def has_add_permission(self, request, user=None):
        if request.user.is_superuser:
            return True
        if request.user.is_authenticated:
            return True
        raise PermissionDenied

class AdminTypePermission(admin.ModelAdmin):
    def has_add_permission(self, request):
        if request.user.is_superuser:
            return True
        raise PermissionDenied

    def has_change_permission(self, request, user=None):
        if request.user.is_superuser:
            return True
        raise PermissionDenied

    def has_delete_permission(self, request, user=None):
        if request.user.is_superuser:
            return True
        raise PermissionDenied
