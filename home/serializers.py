import ast
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from rest_framework import serializers

from home.models import (
    UserProfile,

)
from core.modules.email_template import account_opening_email, send_token_to_email
from core.modules.exceptions import InvalidRequestException
from core.modules.utils import *
from core.modules.choices import (
    ROLE_CHOICES,

)




class ProfileSeriializerOut(serializers.ModelSerializer):
    phoneNumber = serializers.CharField(source="phone_number")
    passwordChanged = serializers.BooleanField(source="password_changed")
    updatedOn = serializers.CharField(source="updated_on")
    createdBy = serializers.CharField(source="created_by")
    createdOn = serializers.CharField(source="created_on")



    class Meta:
        model = UserProfile
        exclude = [
            "id",
            "created_on",
            "otp",
            "otp_expiry",
            "user",
            "phone_number",
            "password_changed",
            "updated_on",
            "created_by",
        ]


class UserSerializerOut(serializers.ModelSerializer):
    firstName = serializers.CharField(source="first_name")
    lastName = serializers.CharField(source="last_name")
    lastLogin = serializers.CharField(source="last_login")
    dateJoined = serializers.CharField(source="date_joined")
    userDetail = serializers.SerializerMethodField()

    def get_userDetail(self, obj):
        request = self.context.get("request")
        user = UserProfile.objects.get(user=obj.id)
        return ProfileSeriializerOut(user, context={"request": request}).data

    class Meta:
        model = User
        exclude = [
            "is_staff",
            "is_active",
            "is_superuser",
            "password",
            "first_name",
            "last_name",
            "groups",
            "user_permissions",
            "last_login",
            "date_joined",
        ]


class UserSerializerIn(serializers.Serializer):
    current_user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    firstName = serializers.CharField()
    lastName = serializers.CharField()
    email = serializers.EmailField()
    phoneNo = serializers.CharField(max_length=15)
    role = serializers.ChoiceField(choices=ROLE_CHOICES)
    institutionId = serializers.CharField(required=False)

    def create(self, validated_data):
        auth_user = validated_data.get("current_user")
        first_name = validated_data.get("firstName")
        last_name = validated_data.get("lastName")
        email = validated_data.get("email")
        phone_no = validated_data.get("phoneNo")
        role = validated_data.get("role")
        institution_id = validated_data.get("institutionId")

        auth_profile = UserProfile.objects.get(user=auth_user)
        non_administrator = ["instUser1", "instUser2"]

        if auth_profile.institution is not None:
            org = auth_profile.institution

        elif role in non_administrator:
            if not institution_id:
                raise InvalidRequestException(
                    api_response(message="Institution code is required", status=False)
                )

        elif auth_profile.role in non_administrator:
            raise InvalidRequestException(
                api_response(
                    message="You are not permitted to perform this action", status=False
                )
            )
        else:
            org = None

        # Reformat Phone Number
        phone_number = format_phone_number(phone_no)

        # Check if user with same email already exist
        if User.objects.filter(email__iexact=email).exists():
            raise InvalidRequestException(
                api_response(message="User with this email already exist", status=False)
            )

        # Generate random password
        random_password = generate_random_password()
        log_request(f"random password: {random_password}")
        # Create user
        user = User.objects.create(
            username=email,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=make_password(random_password),
        )

        # Create Profile
        user_profile = UserProfile.objects.create(
            user=user,
            phone_number=phone_number,
            role=role,
            created_by=auth_user,
            institution=org,
        )

        # Send OTP to user
        Thread(
            target=account_opening_email, args=[user_profile, str(random_password)]
        ).start()
        headers = self.context.get("request").headers
        perform_audit(headers, f"Created new {role} user: {email}", auth_user)

        return UserSerializerOut(
            user, context={"request": self.context.get("request")}
        ).data


class LoginSerializerIn(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def create(self, validated_data):
        email = validated_data.get("email")
        password = validated_data.get("password")

        user = authenticate(username=email, password=password)
        if not user:
            # Create Audit
            headers = self.context.get("request").headers
            perform_audit(headers, f"Failed Login attempt with email: {email}", None)
            response = api_response(
                message="Invalid email or password",
                status=False,
                data={"passwordChanged": False},
            )
            raise InvalidRequestException(response)

        user_profile = UserProfile.objects.get(user=user)
        if not user_profile.password_changed:
            # OTP Timeout
            expiry = get_next_minute(timezone.now(), 15)
            random_otp = generate_random_otp()
            encrypted_otp = encrypt_text(random_otp)
            user_profile.otp = encrypted_otp
            user_profile.otp_expiry = expiry
            user_profile.save()

            # Send OTP to user
            Thread(target=send_token_to_email, args=[user_profile]).start()
            response = api_response(
                message="Kindly change your default password",
                status=False,
                data={"passwordChanged": False, "userId": user.id},
            )
            raise InvalidRequestException(response)

        # Create Audit
        headers = self.context.get("request").headers
        perform_audit(headers, f"Login success", user)

        return user


class ConfirmOTPSerializerIn(serializers.Serializer):
    userId = serializers.CharField(required=False)
    otp = serializers.CharField()

    def create(self, validated_data):
        user_id = validated_data.get("userId")
        otp = validated_data.get("otp")

        auth_user = self.context.get("request").user

        try:
            if not auth_user.is_authenticated:
                user_detail = UserProfile.objects.get(user_id=user_id)
            else:
                user_detail = UserProfile.objects.get(user=auth_user)

        except UserProfile.DoesNotExist:
            response = api_response(message="User not found", status=False)
            raise InvalidRequestException(response)

        if otp != decrypt_text(user_detail.otp):
            response = api_response(message="Invalid OTP", status=False)
            raise InvalidRequestException(response)

        # If OTP has expired
        if timezone.now() > user_detail.otpExpiry:
            response = api_response(
                message="OTP has expired, kindly request for another one", status=False
            )
            raise InvalidRequestException(response)

        return UserSerializerOut(
            user_detail.user, context={"request": self.context.get("request")}
        ).data


class RequestOTPSerializerIn(serializers.Serializer):
    email = serializers.EmailField(required=False)

    def create(self, validated_data):
        email = validated_data.get("email")

        try:
            user_detail = UserProfile.objects.get(user__email=email)
        except UserProfile.DoesNotExist:
            response = api_response(message="User not found", status=False)
            raise InvalidRequestException(response)

        expiry = get_next_minute(timezone.now(), 15)
        random_otp = generate_random_otp()
        log_request(random_otp)
        encrypted_otp = encrypt_text(random_otp)
        user_detail.otp = encrypted_otp
        user_detail.otp_expiry = expiry
        user_detail.save()

        # Send OTP to user
        Thread(target=send_token_to_email, args=[user_detail]).start()
        return {"userId": user_detail.user_id}


class ChangePasswordSerializerIn(serializers.Serializer):
    userId = serializers.CharField(required=False)
    otp = serializers.CharField(required=False)
    oldPassword = serializers.CharField()
    newPassword = serializers.CharField()
    confirmPassword = serializers.CharField()

    def create(self, validated_data):
        user_id = validated_data.get("userId")
        old_password = validated_data.get("oldPassword")
        otp = validated_data.get("otp")
        new_password = validated_data.get("newPassword")
        confirm_password = validated_data.get("confirmPassword")

        user = self.context.get("request").user

        if not user.is_authenticated:
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                response = api_response(message="User not found", status=False)
                raise InvalidRequestException(response)

        if not user.userprofile.password_changed and not otp:
            response = api_response(
                message="OTP is required to change password for the first time",
                status=False,
            )
            raise InvalidRequestException(response)

        if otp:
            # Validate
            if otp != decrypt_text(user.userprofile.otp):
                response = api_response(message="Invalid OTP", status=False)
                raise InvalidRequestException(response)

            # If OTP has expired
            if timezone.now() > user.userprofile.otp_expiry:
                response = api_response(
                    message="OTP has expired, kindly request for another one",
                    status=False,
                )
                raise InvalidRequestException(response)

        if not user.check_password(old_password):
            response = api_response(message="Old password is not valid", status=False)
            raise InvalidRequestException(response)

        success, text = password_checker(password=new_password)
        if not success:
            response = api_response(message=text, status=False)
            raise InvalidRequestException(response)

        # Check if newPassword and confirmPassword match
        if new_password != confirm_password:
            response = api_response(message="Passwords mismatch", status=False)
            raise InvalidRequestException(response)

        # Check if new and old passwords are the same
        if old_password == new_password:
            response = api_response(
                message="Old and New Passwords cannot be the same", status=False
            )
            raise InvalidRequestException(response)

        user.password = make_password(password=new_password)
        user.userprofile.password_changed = True
        user.save()
        user.userprofile.save()
        headers = self.context.get("request").headers
        perform_audit(headers, f"Password Changed Successfully", user)
        return "Password Changed Successfully"


class ForgotPasswordSerializerIn(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
    newPassword = serializers.CharField()
    confirmPassword = serializers.CharField()

    def create(self, validated_data):
        email = validated_data.get("email")
        otp = validated_data.get("otp")
        password = validated_data.get("newPassword")
        confirm_password = validated_data.get("confirmPassword")

        try:
            user_detail = UserProfile.objects.get(user__email=email)
        except UserProfile.DoesNotExist:
            response = api_response(message="User not found", status=False)
            raise InvalidRequestException(response)

        if timezone.now() > user_detail.otp_expiry:
            response = api_response(
                message="OTP has expired, Please request for another one", status=False
            )
            raise InvalidRequestException(response)

        if otp != decrypt_text(user_detail.otp):
            response = api_response(message="Invalid OTP", status=False)
            raise InvalidRequestException(response)

        success, msg = password_checker(password=password)
        if not success:
            raise InvalidRequestException(api_response(message=msg, status=False))

        if password != confirm_password:
            raise InvalidRequestException(
                api_response(message="Passwords does not match", status=False)
            )

        user_detail.user.password = make_password(password)
        user_detail.user.save()
        # headers = self.context.get("request").headers
        # perform_audit(headers, f"Password reset", user_detail.user)

        return "Password reset successful"




class AuditSerializerOut(serializers.ModelSerializer):
    actionBy = serializers.CharField(source="user")
    sourceAddress = serializers.SerializerMethodField()
    createdOn = serializers.DateTimeField(source="created_on")

    def get_sourceAddress(self, obj):
        if obj.source:
            return decrypt_text(obj.source)
        return None

    class Meta:
        model = Audit
        exclude = ["source", "user", "created_on"]


