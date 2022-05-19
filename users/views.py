from django.core.paginator import Paginator
from rest_framework import status, permissions
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import CustomUser
from .serializers import GetUserSerializer, ResisterUserSerializer, AuthTokenSerializer, ChangePasswordSerializer, \
    SendPasswordResetEmailSerializer, UserPasswordResetSerializer, SendEmailVerificationCodeSerializer, \
    UpdateProfileSerializer


class SendEmailVerificationCodeView(APIView):
    def post(self, request, format=None):
        serializer = SendEmailVerificationCodeSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)

        return Response(status=status.HTTP_200_OK, data={
            "message": "Check your email"
        })


class RegisterUserView(APIView):
    def post(self, request, format=None):
        print("data", request.data)
        serializer = ResisterUserSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response(status=status.HTTP_201_CREATED, data={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "fullname": user.fullname
            })
        return Response(status=status.HTTP_400_BAD_REQUEST, data={
            "message": serializer.errors,
            "data": {}
        })


class UpdateProfileView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, *args, **kwargs):
        user = self.request.user

        username = request.data.get("username")

        duplicate_user = CustomUser.objects.filter(username=username)

        if len(duplicate_user) > 0:
            response = {
                'message': 'Username already exist',
            }
            return Response(status=status.HTTP_400_BAD_REQUEST, data=response)

        serializer = UpdateProfileSerializer(user, data=request.data, partial=True)

        serializer.is_valid(raise_exception=True)

        serializer.save()

        response = {
            'message': 'Profile updated successfully',
        }

        return Response(status=status.HTTP_201_CREATED, data=response)


class GetUsersView(APIView):
    def get(self, request, *args, **kwargs):
        page_number = request.query_params.get('page_number', 1)
        page_size = request.query_params.get('page_size', 10)
        address = request.query_params.get('address')
        blood_group_query = request.query_params.get('blood_group')

        if blood_group_query:
            blood_group = blood_group_query.split(",")

        try:
            if blood_group_query and address:
                users = CustomUser.objects.filter(blood_group__in=blood_group, address=address)
                total_count = CustomUser.objects.filter(blood_group__in=blood_group, address=address).count()

            elif blood_group_query:
                users = CustomUser.objects.filter(is_staff=False, available=True, blood_group__in=blood_group)
                total_count = CustomUser.objects.filter(is_staff=False, available=True, blood_group__in=blood_group).count()

            elif address:
                users = CustomUser.objects.filter(is_staff=False, available=True, address=address)
                total_count = CustomUser.objects.filter(is_staff=False, available=True, address=address).count()

            else:
                users = CustomUser.objects.filter(is_staff=False, available=True)
                total_count = CustomUser.objects.filter(is_staff=False, available=True).count()

        except Exception:
            response = dict(message='Failed to fetched users', data=[])
            return Response(status=status.HTTP_400_BAD_REQUEST, data=response)

        paginator = Paginator(users, page_size)

        serializer = GetUserSerializer(paginator.page(page_number), many=True)

        response = {
            'message': 'List of users fetched successfully',
            'data': serializer.data,
            "total_count": total_count
        }

        return Response(status=status.HTTP_200_OK, data=response)


class GetUserDetailView(APIView):
    def get(self, request, *args, **kwargs):
        pk = self.kwargs['pk']

        try:
            author = CustomUser.objects.get(pk=pk)
        except Exception:
            response = dict(message='User of provided id does not exist', data={})
            return Response(status=status.HTTP_400_BAD_REQUEST, data=response)
        serializer = GetUserSerializer(author)

        response = {
            'message': 'User data fetched successfully',
            'data': serializer.data
        }

        return Response(status=status.HTTP_200_OK, data=response)


class LoginAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = AuthTokenSerializer(data=request.data,
                                         context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)

        response = {
            "message": 'Login Successfull',
            "data": {
                'token': token.key,
                "id": user.id,
                'email': user.email,
                'fullname': user.fullname,
            }
        }

        return Response(status=status.HTTP_200_OK, data=response)


class IsLoginView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        response = {
            "message": "Authenticated",
            "data": []
        }
        return Response(status=status.HTTP_200_OK, data=response)


class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = self.request.user
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            print("op", serializer.data)
            if not user.check_password(serializer.data.get("old_password")):
                response = {
                    "message": "Incorrect old password",
                }
                return Response(status=status.HTTP_401_UNAUTHORIZED, data=response)

            if serializer.data.get("old_password") == serializer.data.get("new_password"):
                response = {
                    "message": "You can not change to old password. Try new one",
                }

                return Response(status=status.HTTP_400_BAD_REQUEST, data=response)

            user.set_password(serializer.data.get("new_password"))
            user.save()

            response = {
                "message": "Password Changed Successfully",
                "data": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username,
                    "fullname": user.fullname

                }
            }

            return Response(status=status.HTTP_200_OK, data=response)

        response = {
            "message": serializer.errors,
            "data": {}
        }

        return Response(status=status.HTTP_400_BAD_REQUEST, data=response)


class SendPasswordResetEmailView(APIView):
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)

        serializer.is_valid(raise_exception=True)

        return Response(status=status.HTTP_200_OK, data={
            "message": "Check your email"
        })


class UserPasswordResetView(APIView):
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        serializer.is_valid(raise_exception=True)

        return Response(status=status.HTTP_200_OK, data={
            "message": "Password Reset Successflly"
        })
