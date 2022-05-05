from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from .models import CustomUser, EmailToken
from .utils import Util, generate_random_digits


class SendEmailVerificationCodeSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate(self, attrs):
        email = attrs.get("email")

        # Check is email is already registered
        authors = CustomUser.objects.filter(email=email)
        if len(authors) > 0:
            raise serializers.ValidationError("Provided email is already registered in our system.")

        # Check if verification code is already sent
        email_token = EmailToken.objects.filter(email=email)
        if len(email_token) > 0:
            for i in email_token:
                i.delete()

        # Save new email_token instance
        token = generate_random_digits(6)
        body = "We received a request to verify your email. Enter this code to complete the verification " \
               "process. " + str(
            token)
        data = {
            "subject": "Verify Email",
            "body": body,
            "to_email": email
        }
        email_token = EmailToken(
            email=email,
            token=token
        )
        email_token.save()

        # Send email with verification code
        try:
            Util.send_mail(data)
        except Exception:

            # Delete email_token_instace if email was not sent
            try:
                email_token = EmailToken.objects.get(email=email)
                email_token.delete()
            except ObjectDoesNotExist:
                pass

            raise serializers.ValidationError("Could not send the mail")

        return attrs

    def create(self, validated_data):
        pass

    def update(self, instance, validated_data):
        pass


class ResisterUserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)
    token = serializers.IntegerField(required=True)

    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'fullname', 'password', 'confirm_password', 'token']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, attrs):
        token = attrs.get("token")
        email = attrs.get("email")

        try:
            email_token = EmailToken.objects.get(email=email, token=token)
            email_token.delete()

            password = attrs.get("password")
            confirm_password = attrs.get("confirm_password")

            if password != confirm_password:
                raise serializers.ValidationError("Password and confirm passsword does not match.")

            return attrs

        except ObjectDoesNotExist:
            raise serializers.ValidationError("Email verification token does not match")

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        validated_data.pop("token")
        return CustomUser.objects.create_user(**validated_data)


class GetUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'username', 'fullname']


class AuthTokenSerializer(serializers.Serializer):
    email = serializers.CharField(
        label=_("Email"),
        write_only=True
    )
    password = serializers.CharField(
        label=_("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )
    token = serializers.CharField(
        label=_("Token"),
        read_only=True
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'),
                                email=email, password=password)

            # The authenticate call simply returns None for is_active=False
            # users. (Assuming the default ModelBackend authentication
            # backend.)
            if not user:
                msg = _('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs

    def create(self, validated_data):
        pass

    def update(self, instance, validated_data):
        pass


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def create(self, validated_data):
        pass

    def update(self, instance, validated_data):
        pass


class SendPasswordResetEmailSerializer(serializers.Serializer):
    def create(self, validated_data):
        pass

    def update(self, instance, validated_data):
        pass

    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get("email")
        if CustomUser.objects.filter(email=email).exists():
            user = CustomUser.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded UID', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("Password reset token", token)
            link = 'http://localhost:3000/auth/reset-password/' + uid + "/" + token
            print('Password Reset Link', link)
            body = "Click Following Link to Reset Your Password " + link

            data = {
                "subject": "Reset Your Password",
                "body": body,
                "to_email": user.email
            }

            try:
                Util.send_mail(data)
            except Exception:
                raise serializers.ValidationError("Could not send the mail")

            return attrs
        else:
            raise serializers.ValidationError("You are not a Registered User")


class UserPasswordResetSerializer(serializers.Serializer):
    def create(self, validated_data):
        pass

    def update(self, instance, validated_data):
        pass

    password = serializers.CharField(required=True, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')
            uid = self.context.get("uid")
            token = self.context.get("token")

            if password != confirm_password:
                raise serializers.ValidationError("Password and confirm password didn't match")

            userid = smart_str(urlsafe_base64_decode(uid))
            user = CustomUser.objects.get(pk=userid)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Token is not valid or expired")

            user.set_password(password)
            user.save()
            return attrs

        except DjangoUnicodeDecodeError as indentifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError("Token is not valid or expired")
