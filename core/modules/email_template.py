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

