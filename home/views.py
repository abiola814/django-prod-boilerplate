from django.db import connections
from drf_spectacular.utils import extend_schema, OpenApiParameter
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.types import OpenApiTypes
from django.shortcuts import get_object_or_404
from django.db.models import Q
from .serializers import *
from core.modules.exceptions import raise_serializer_error_msg
from core.modules.utils import incoming_request_checks, api_response,get_incoming_request_checks
from core.modules.paginations import CustomPagination

import threading
from core.modules.utils import api_response, get_incoming_request_checks, generate_and_send_csv, generate_csv


@extend_schema(request=UserSerializerIn, responses={status.HTTP_201_CREATED})
class CreateUserAPIView(APIView):
    permission_classes = []

    def post(self, request):
        status_, data = incoming_request_checks(request)
        if not status_:
            return Response(api_response(message=data, status=False), status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializerIn(data=data, context={"request": request})
        serializer.is_valid() or raise_serializer_error_msg(errors=serializer.errors)
        response = serializer.save()
        return Response(api_response(message="Account created successfully", status=True, data=response))


@extend_schema(request=LoginSerializerIn, responses={status.HTTP_200_OK})
class LoginAPIView(APIView):
    permission_classes = []

    def post(self, request):
        status_, data = incoming_request_checks(request)
        if not status_:
            return Response(api_response(message=data, status=False), status=status.HTTP_400_BAD_REQUEST)
        serializer = LoginSerializerIn(data=data, context={"request": request})
        serializer.is_valid() or raise_serializer_error_msg(errors=serializer.errors)
        user = serializer.save()
        return Response(api_response(message="Login successful", status=True, data={
            "userData": UserSerializerOut(user, context={"request": request}).data,
            "accessToken": RefreshToken.for_user(user).access_token, "passwordChanged": user.userprofile.password_changed}))


@extend_schema(request=ConfirmOTPSerializerIn, responses={status.HTTP_200_OK})
class ConfirmOTPView(APIView):
    permission_classes = []
    
    def post(self, request):
        status_, data = incoming_request_checks(request)
        if not status_:
            return Response(api_response(message=data, status=False), status=status.HTTP_400_BAD_REQUEST)

        serializer = ConfirmOTPSerializerIn(data=data, context={"request": request})
        serializer.is_valid() or raise_serializer_error_msg(errors=serializer.errors)
        response = serializer.save()
        return Response(api_response(message="OTP verified successfully", data=response, status=True))


@extend_schema(request=RequestOTPSerializerIn, responses={status.HTTP_200_OK})
class RequestOTPView(APIView):
    permission_classes = []

    def post(self, request):
        status_, data = incoming_request_checks(request)
        if not status_:
            return Response(api_response(message=data, status=False), status=status.HTTP_400_BAD_REQUEST)

        serializer = RequestOTPSerializerIn(data=data, context={"request": request})
        serializer.is_valid() or raise_serializer_error_msg(errors=serializer.errors)
        response = serializer.save()
        return Response(api_response(message="OTP has been sent to your email address", data=response, status=True))


@extend_schema(request=ChangePasswordSerializerIn, responses={status.HTTP_200_OK})
class ChangePasswordView(APIView):
    permission_classes = []

    def post(self, request):
        status_, data = incoming_request_checks(request)
        if not status_:
            return Response(api_response(message=data, status=False), status=status.HTTP_400_BAD_REQUEST)

        serializer = ChangePasswordSerializerIn(data=data, context={"request": request})
        serializer.is_valid() or raise_serializer_error_msg(errors=serializer.errors)
        response = serializer.save()
        return Response(api_response(message=response, status=True))


@extend_schema(request=ForgotPasswordSerializerIn, responses={status.HTTP_200_OK})
class ForgotPasswordView(APIView):
    permission_classes = []

    def post(self, request):
        status_, data = incoming_request_checks(request)
        if not status_:
            return Response(api_response(message=data, status=False), status=status.HTTP_400_BAD_REQUEST)

        serializer = ForgotPasswordSerializerIn(data=data)
        serializer.is_valid() or raise_serializer_error_msg(errors=serializer.errors)
        response = serializer.save()
        return Response(api_response(message=response, status=True))




class AuditAPIView(APIView, CustomPagination):
    @extend_schema(
        description="Retrieve a list of audit logs.",
        parameters=[
            OpenApiParameter(name="start_date", type=OpenApiTypes.DATE, description="Start date for filtering transactions (YYYY-MM-DD)"),
            OpenApiParameter(name="end_date", type=OpenApiTypes.DATE, description="End date for filtering transactions (YYYY-MM-DD)"),    
            OpenApiParameter(name="download", type=OpenApiTypes.STR),
        ],
        responses={status.HTTP_200_OK: AuditSerializerOut(many=True)}
    )
    def get(self, request):
        status_, data_ = get_incoming_request_checks(request)
        if not status_:
            return Response(api_response(message=data_, status=False), status=status.HTTP_400_BAD_REQUEST)

        if not UserProfile.objects.filter(role="admin", user=request.user).exists():
            return Response(
                api_response(message="You are not permitted to perform this action", status=False),
                status=status.HTTP_400_BAD_REQUEST
            )
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")
        download = request.GET.get("download")
        query = Q()
        if start_date:
            if end_date:
                query &= Q(created_on__range=(start_date, end_date))
            else:
                return Response(api_response(message="Please indicate the start and end date", status=False), status=status.HTTP_400_BAD_REQUEST)
        queryset = Audit.objects.filter(query).order_by("-created_on")
        if download:
            if queryset.count() > 50000:
                thread = threading.Thread(target=generate_and_send_csv, args=(request, queryset, Audit, request.user.username))
                thread.start()

                return Response(api_response(message=f"CSV file sent to {request.user.username}", status=True))
            else:
                data = generate_csv(queryset, Audit)
                return data

        # List all Audits
        queryset = self.paginate_queryset(queryset, request)
        data = self.get_paginated_response(AuditSerializerOut(queryset, many=True).data).data
        return Response(api_response(message="Success", status=True, data=data))


