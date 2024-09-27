import os
import base64
import calendar
import datetime
import logging
import re
import secrets
import csv
from django.contrib.sites.models import Site
from django.utils import timezone
from cryptography.fernet import Fernet
from django.conf import settings
from django.utils.crypto import get_random_string
from dateutil.relativedelta import relativedelta
from home.models import SiteSetting
from django.shortcuts import render
from django.http import HttpResponse
from threading import Thread
from home.models import Audit
import requests
import json


from Crypto.Cipher import AES


def log_request(*args):
    for arg in args:
        logging.info(arg)


def encrypt_text(text: str):
    key = base64.urlsafe_b64encode(settings.SECRET_KEY.encode()[:32])
    fernet = Fernet(key)
    secure = fernet.encrypt(f"{text}".encode())
    return secure.decode()


def generate_csv(queryset, model_name):
    # Get the model fields and extract their names
    fields = model_name._meta.fields
    header = [field.name for field in fields]

    # Create a CSV file in memory
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = (
        f"attachment; filename={model_name.__name__.lower()}_data.csv"
    )

    csv_writer = csv.writer(response)
    csv_writer.writerow(header)

    for obj in queryset:
        row_data = []
        for field in header:
            value = getattr(obj, field)

            row_data.append(value)
        csv_writer.writerow(row_data)

    return response


# Function to generate and send CSV with masked PAN field
def generate_and_send_csv(request, queryset, model_name, recipient_email):
    from core.modules.utils import send_email

    # Get the model fields and extract their names
    fields = model_name._meta.get_fields()
    header = [field.name for field in fields]

    # Create a CSV file in the media directory
    media_path = os.path.join(settings.MEDIA_ROOT, "csv_files")
    os.makedirs(media_path, exist_ok=True)
    csv_file_path = os.path.join(media_path, f"{model_name.__name__.lower()}_data.csv")

    with open(csv_file_path, "w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(header)

        for obj in queryset:
            row_data = []
            for field in header:
                value = getattr(obj, field)

                row_data.append(value)
            csv_writer.writerow(row_data)

    # Construct the download link
    base_url = settings.BASE_URL.rstrip("/")
    relative_csv_path = os.path.relpath(csv_file_path, settings.MEDIA_ROOT)
    download_link = f"{base_url}/media/csv_files/{model_name.__name__.lower()}_data.csv"

    first_name = request.user.first_name
    email = recipient_email
    if not request.user.first_name:
        first_name = "Core Admin"

    message = (
        f"Dear {first_name}, <br><br>Kindly click on the below link to download your requested report. <br>"
        f"<p/>Click the button below to download the file <p/>"
        f"<div style='text-align:left'><a href='{download_link}' target='_blank' "
        f"style='background-color: #67C1F0; color: white; padding: 15px 25px; text-align: center; "
        f"text-decoration: none; display: inline-block;'>Download</a></div><br>"
    )
    subject = "Report Download"
    contents = render(
        None, "default_template.html", context={"message": message}
    ).content.decode("utf-8")
    send_email(contents, email, subject)
    return "Email sent successfully."


def decrypt_text(text: str):
    key = base64.urlsafe_b64encode(settings.SECRET_KEY.encode()[:32])
    fernet = Fernet(key)
    decrypt = fernet.decrypt(text.encode())
    return decrypt.decode()


def generate_random_password():
    return get_random_string(length=10)


def generate_random_otp():
    return get_random_string(length=6, allowed_chars="1234567890")


def get_previous_date(date, delta):
    previous_date = date - relativedelta(days=delta)
    return previous_date

def send_email(content, email, subject):
    d_site = get_site_details()
    email_url = settings.EMAIL_URL

    payload = json.dumps({"Message": content, "address": email, "Subject": subject})
    log_request(f"record to be sent to email ", {payload})
    response = requests.request(
        "POST", email_url, headers={"Content-Type": "application/json"}, data=payload
    )
    log_request(f"Sending email to: {email}\nResponse: {response.text}")
    return response.text


def create_audit(**kwargs):
    audit = Audit(**kwargs)
    audit.save()


def perform_audit(headers, action, user, method="POST"):
    data_source = headers.get("ipAddress")
    browser = headers.get("browser")
    system = headers.get("os")
    device = headers.get("device")

    source = encrypt_text(data_source)

    # Create Audit
    create_audit(
        action=action,
        user=user,
        source=source,
        browser=browser,
        system=system,
        method=method,
        device=device,
    )

    return True


def get_next_date(date, delta):
    next_date = date + relativedelta(days=delta)
    return next_date


def get_next_minute(date, delta):
    next_minute = date + relativedelta(minutes=delta)
    return next_minute


def get_previous_minute(date, delta):
    previous_minute = date - relativedelta(minutes=delta)
    return previous_minute


def get_previous_seconds(date, delta):
    previous_seconds = date - relativedelta(seconds=delta)
    return previous_seconds


def get_previous_hour(date, delta):
    previous_hour = date - relativedelta(hours=delta)
    return previous_hour


def get_day_start_and_end_datetime(date_time):
    day_start = date_time - relativedelta(day=0)
    # day_end = day_start + relativedelta(day=0)
    day_end = day_start + relativedelta(days=1)
    day_start = day_start.date()
    # day_start = datetime.datetime.combine(day_start.date(), datetime.time.min)
    # day_end = datetime.datetime.combine(day_end.date(), datetime.time.max)
    day_end = day_end.date()
    return day_start, day_end


def get_week_start_and_end_datetime(date_time):
    week_start = date_time - datetime.timedelta(days=date_time.weekday())
    week_end = week_start + datetime.timedelta(days=6)
    week_start = datetime.datetime.combine(week_start.date(), datetime.time.min)
    week_end = datetime.datetime.combine(week_end.date(), datetime.time.max)
    return week_start, week_end


def get_month_start_and_end_datetime(date_time):
    month_start = date_time.replace(day=1)
    month_end = month_start.replace(
        day=calendar.monthrange(month_start.year, month_start.month)[1]
    )
    month_start = datetime.datetime.combine(month_start.date(), datetime.time.min)
    month_end = datetime.datetime.combine(month_end.date(), datetime.time.max)
    return month_start, month_end


def get_month_range(delta):
    current_date = timezone.now()
    start = (current_date - relativedelta(months=delta)).replace(day=1)
    end = (start + relativedelta(months=1)).replace(day=1) - relativedelta(days=1)
    return start, end


def get_year_start_and_end_datetime(date_time):
    year_start = date_time.replace(day=1, month=1, year=date_time.year)
    year_end = date_time.replace(day=31, month=12, year=date_time.year)
    year_start = datetime.datetime.combine(year_start.date(), datetime.time.min)
    year_end = datetime.datetime.combine(year_end.date(), datetime.time.max)
    return year_start, year_end


def get_previous_month_date(date, delta):
    return date - relativedelta(months=delta)


def get_next_month_date(date, delta):
    return date + relativedelta(months=delta)


# def send_email(content, email, subject):
#     payload = json.dumps({
#         "personalizations": [{"to": [{"email": email}]}], "from": {"email": email_from, "name": "divebusters"},
#         "subject": subject, "content": [{"type": "text/html", "value": content}]
#     })
#     response = requests.request(
#         "POST", email_url, headers={"Content-Type": "application/json", "Authorization": f"Bearer {email_api_key}"},
#         data=payload
#     )
#     log_request(f"Sending email to: {email}\nResponse: {response.text}")
#     return response.text


def password_checker(password: str):
    try:
        # Python program to check validation of password
        # Module of regular expression is used with search()

        flag = 0
        while True:
            if len(password) < 8:
                flag = -1
                break
            elif not re.search("[a-z]", password):
                flag = -1
                break
            elif not re.search("[A-Z]", password):
                flag = -1
                break
            elif not re.search("[0-9]", password):
                flag = -1
                break
            elif not re.search("[#!_@$-]", password):
                flag = -1
                break
            elif re.search("\s", password):
                flag = -1
                break
            else:
                flag = 0
                break

        if flag == 0:
            return True, "Valid Password"

        return (
            False,
            "Password must contain uppercase, lowercase letters, '# ! - _ @ $' special characters "
            "and 8 or more characters",
        )
    except (Exception,) as err:
        return False, f"{err}"


def validate_email(email):
    try:
        regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        if re.fullmatch(regex, email):
            return True
        return False
    except (TypeError, Exception) as err:
        # Log error
        return False


def get_site_details():
    try:
        site, created = SiteSetting.objects.get_or_create(
            site=Site.objects.get_current()
        )
    except Exception as ex:
        logging.exception(str(ex))
        site = SiteSetting.objects.filter(site=Site.objects.get_current()).first()
    return site


def mask_character(number_to_mask, num_chars_to_mask, mask_char="*"):
    if len(number_to_mask) <= num_chars_to_mask:
        return mask_char * len(number_to_mask)
    else:
        return mask_char * num_chars_to_mask + number_to_mask[num_chars_to_mask:]


def create_notification(user, text):
    # notify = Notification.objects.create(message=text)
    # notify.user.add(user)
    return True


def api_response(message, status, data=None, **kwargs):
    if data is None:
        data = {}
    try:
        reference_id = secrets.token_hex(30)
        response = dict(
            requestTime=timezone.now(),
            requestType="outbound",
            referenceId=reference_id,
            status=bool(status),
            message=message,
            data=data,
            **kwargs,
        )

        # if "accessToken" in data and 'refreshToken' in data:
        if "accessToken" in data:
            # Encrypting tokens to be
            response["data"]["accessToken"] = encrypt_text(text=data["accessToken"])
            # response['data']['refreshToken'] = encrypt_text(text=data['refreshToken'])
            logging.info(msg=response)

            response["data"]["accessToken"] = decrypt_text(text=data["accessToken"])
            # response['data']['refreshToken'] = encrypt_text(text=data['refreshToken'])

        else:
            logging.info(msg=response)

        return response
    except (Exception,) as err:
        return err


def incoming_request_checks(request, require_data_field: bool = True) -> tuple:
    try:
        x_api_key = request.headers.get("X-Api-Key", None) or request.META.get(
            "HTTP_X_API_KEY", None
        )
        request_type = request.data.get("requestType", None)
        data = request.data.get("data", {})

        if not x_api_key:
            return False, "Missing or Incorrect Request-Header field 'X-Api-Key'"

        if x_api_key != settings.X_API_KEY:
            return False, "Invalid value for Request-Header field 'X-Api-Key'"

        if not request_type:
            return False, "'requestType' field is required"

        if request_type != "inbound":
            return False, "Invalid 'requestType' value"

        if require_data_field:
            if not data:
                return (
                    False,
                    "'data' field was not passed or is empty. It is required to contain all request data",
                )

        return True, data
    except (Exception,) as err:
        return False, f"{err}"


def get_incoming_request_checks(request) -> tuple:
    try:
        x_api_key = request.headers.get("X-Api-Key", None) or request.META.get(
            "HTTP_X_API_KEY", None
        )

        if not x_api_key:
            return False, "Missing or Incorrect Request-Header field 'X-Api-Key'"

        if x_api_key != settings.X_API_KEY:
            return False, "Invalid value for Request-Header field 'X-Api-Key'"

        return True, ""
        # how do I handle requestType and also client ID e.g 'inbound', do I need to expect it as a query parameter.
    except (Exception,) as err:
        return False, f"{err}"


def format_phone_number(phone_number):
    return f"234{phone_number[:10]}"


def decrypt_pin(content):
    encryption_key = settings.DECRYPTION_KEY
    key = bytes.fromhex(encryption_key)
    data = bytes.fromhex(content)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(data)
    data = bytes(decrypted_data.decode("utf-8"), "utf-8")
    return data.rstrip(b"\x00").decode("utf-8")


def transaction_pin_correct(user, trans_pin):
    decrypted_pin = decrypt_pin(trans_pin)
    correct_pin = decrypt_text(user.userprofile.transactionPin)
    if str(decrypted_pin) != str(correct_pin):
        return False
    return True
