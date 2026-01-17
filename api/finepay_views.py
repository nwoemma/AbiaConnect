from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from accounts.models import User
from .serializers import UserSerializer

@api_view(['POST'])
@permission_classes([AllowAny])
def sign_up(request):
    full_name = request.data.get('full_name', '')
    name_parts = full_name.split()
    first_name = name_parts[0] if len(name_parts) > 0 else ''
    last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
    phone = request.data.get('phone')
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email or not password:
        return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)
    if User.objects.filter(email=email).exists():
        return Response({'error': 'Email already in use'}, status=status.HTTP_409_CONFLICT)
    if User.objects.filter(phone=phone).exists():
        return Response({'error': 'Phone number already in use'}, status=status.HTTP_406_NOT_ACCEPTABLE)
    
    serializer = UserSerializer(data={
        'first_name': first_name,  
        'last_name': last_name,
        'phone': phone,
        'email': email,
        'password': make_password(password)
    })
    
    if serializer.is_valid():
        user = serializer.save()
        return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)