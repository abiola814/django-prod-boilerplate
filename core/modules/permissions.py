from rest_framework.permissions import BasePermission

from home.models import UserProfile


class IsCustomer(BasePermission):
    def has_permission(self, request, view):
        try:
            UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return False

        return True



