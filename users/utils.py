from django.core.mail import EmailMessage
import os
import math
import random


class Util:
    @staticmethod
    def send_mail(data):
        email = EmailMessage(
            data['subject'],
            data['body'],
            os.environ.get("EMAIL_FROM"),
            [data['to_email']]
        )
        email.send()


def generate_random_digits(no_of_digits: int):
    multiplier = 1
    for i in range(0, no_of_digits):
        multiplier *= 10

    token = math.floor(random.random() * multiplier)

    if len(str(token)) < no_of_digits:
        generate_random_digits(no_of_digits)
    else:
        return token