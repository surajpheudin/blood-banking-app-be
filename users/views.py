from rest_framework import status, permissions
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import CustomUser
from .serializers import GetUserSerializer, ResisterUserSerializer, AuthTokenSerializer, ChangePasswordSerializer, \
    SendPasswordResetEmailSerializer, UserPasswordResetSerializer


class RegisterUserView(APIView):
    def post(self, request, format=None):
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


class GetUsersView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            users = CustomUser.objects.filter(is_staff=False)
        except Exception:
            response = dict(message='Failed to fetched users', data=[])
            return Response(status=status.HTTP_400_BAD_REQUEST, data=response)

        serializer = GetUserSerializer(users, many=True)

        response = {
            'message': 'List of users fetched successfully',
            'data': serializer.data
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