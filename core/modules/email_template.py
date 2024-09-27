from django.shortcuts import render
from core.modules.utils import send_email, decrypt_text, get_site_details


def parent_class_creation_email(classroom, lang):
    email = classroom.student.parent.user.email
    first_name = classroom.student.parent.first_name()
    student_name = str(classroom.student.get_full_name()).upper()
    tutor_name = classroom.tutor.first_name
    subject = str(classroom.subjects.name).upper()
    amount = classroom.amount
    if not first_name:
        first_name = "Core Parent"

    message = f"Dear {first_name}, <br><br>Your child/ward: <strong>{student_name}</strong> just created a classroom " \
              f"with a tutor <br>Tutor Name: <strong>{tutor_name}</strong><br>Subject: <strong>{subject}</strong>" \
              f"<br>Amount: <strong>{amount}</strong>"
    subject = "New Class Room Request"
    contents = render(None, 'en_default_template.html', context={'message': message}).content.decode('utf-8')
    send_email(contents, email, subject)
    return True
from upconnect.modules.utils import decrypt_text, send_email, get_site_details

d_site = get_site_details()


def account_opening_email(profile, password):
    first_name = profile.user.first_name
    email = profile.user.email
    if not profile.user.first_name:
        first_name = f"{d_site.site_name_short} User"

    message = f"Dear {first_name}, <br><br>Welcome to <a href='{d_site.frontend_url}' target='_blank'>" \
              f"{d_site.site_name}.</a><br>Please see below, your username " \
              f"and password. You will be required to change your password on your first login <br><br>" \
              f"username: <strong>{email}</strong><br>password: <strong>{password}</strong>"
    subject = f"{d_site.site_name_short} Registration"
    contents = render(None, 'default_template.html', context={'message': message}).content.decode('utf-8')
    send_email(contents, email, subject)
    return True


def send_token_to_email(user_profile):
    first_name = user_profile.user.first_name
    if not user_profile.user.first_name:
        first_name = f"{d_site.site_name_short} Admin"
    email = user_profile.user.email
    decrypted_token = decrypt_text(user_profile.otp)

    message = f"Dear {first_name}, <br><br>Kindly use the below One Time Token, to complete your action<br><br>" \
              f"OTP: <strong>{decrypted_token}</strong>"
    subject = f"OTP from {d_site.site_name_short}"
    contents = render(None, 'default_template.html', context={'message': message}).content.decode('utf-8')
    send_email(contents, email, subject)
    return True
