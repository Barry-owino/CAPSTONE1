from rest_framework import generics, status, permissions
from django.contrib.auth import authenticate
#from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from django.contrib.auth.models import User
from .serializers import UserRegisterSerializer, UserLoginSerializer

# Create your views here.

#class for User Registration(Signup)
class UserRegisterView(generics.GenericAPIView):
    queryset = User.objects.all() # comeback an do more about this, when is it neede in this code and when not
    serializer_class = UserRegisterSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, serializer): # need to know why its named post
        serializer = self.get_serializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'message': 'User registered successfully', 
            'username': user.username, 
            'token': token.key
        }, status=status.HTTP_201_CREATED)


class UserLoginView(generics.GenericAPIView):
    serializer_class  = UserLoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        user = authenticate(username=username, password=password)
        if user:
            token, created =Token.objects.get_or_create(user=user)
            return Response({
                'message': 'Login successfull',
                'username': username,
                'token': token.key
            }, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


