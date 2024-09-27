from django.contrib.sites.models import Site
from django.db import models
from django.contrib.auth.models import User
from core.modules.choices import ROLE_CHOICES


class Audit(models.Model):
    action = models.CharField(max_length=100, blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    source = models.TextField(blank=True, null=True)
    browser = models.CharField(max_length=100, blank=True, null=True)
    system = models.CharField(max_length=100, blank=True, null=True)
    device = models.CharField(max_length=100, blank=True, null=True)
    method = models.CharField(max_length=50, blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user}: {self.action}"


class SiteSetting(models.Model):
    site = models.OneToOneField(Site, on_delete=models.CASCADE)
    site_name = models.CharField(max_length=200, null=True, default="UP Connect Monitoring Dashboard")
    site_name_short = models.CharField(max_length=200, null=True, default="UP Connect")
    email_url = models.CharField(max_length=200, null=True, blank=True)
    email_from = models.CharField(max_length=100, null=True, blank=True)
    email_api_key = models.CharField(max_length=300, null=True, blank=True)
    frontend_url = models.CharField(max_length=300, null=True, blank=True)

    def __str__(self):
        return self.site.name



class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20)
    role = models.CharField(max_length=100, choices=ROLE_CHOICES)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name="user_created_by")
    password_changed = models.BooleanField(default=False)
    otp = models.TextField(blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_on = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user}: {self.role} - {self.created_on}"






