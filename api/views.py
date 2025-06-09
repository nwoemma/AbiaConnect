import logging
import os
import ssl
import certifi
import numpy as np
import pandas
import pandas as pd
import json
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail, get_connection
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.html import strip_tags
from django.views.decorators.csrf import csrf_exempt

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.authtoken.models import Token

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError, AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken

import pickle
from accounts.models import User
from chats.models import Chat, Conversion, ChatDetails, ChatCategory, Message
from news.models import Notification, Announcement,Emergency, Report, Project, Suggestion

from .serializers import (
    AnnouncementSerializer,
    ChatCategorySerializer,
    ChatDetailSerializer,
    ChatSerializer,
    MessageSerializer,
    NotificationSerializer,
    ProfileSerializer,
    UserSerializer,
    EmergencySerializer,
    ReportSerializer,
    SuggestionSerializer,
    ProjectSerializer,
    DashboardSerializer
)
import numpy as np
import datetime
import joblib





logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ssl_context = ssl.create_default_context(cafile=certifi.where())
MODEL_PATH_CAR = os.path.join(settings.BASE_DIR, 'mlresult', 'car_model.pkl')
MODEL_PATH_SENTIMENT = os.path.join(BASE_DIR, 'ml_result', 'NLP.h5')
TOKENIZER_PATH = os.path.join(settings.BASE_DIR, 'mlresult', 'tokenizer.pkl')


regression = joblib.load('mlresult/car_model.pkl')
scaler = joblib.load('mlresult/car_scaler.pkl')
with open('mlresult/car_model_feature_order.txt') as f:
    FEATURE_ORDER = [line.strip() for line in f]


car_model = None
sentiment_model = None
tokenizer = None

BASE_DIR = settings.BASE_DIR


sentiment_model = None
def get_sentiment_model():
    from keras.models import load_model
    global sentiment_model
    if sentiment_model is None:
        if os.path.exists(MODEL_PATH_SENTIMENT):
            sentiment_model = load_model(MODEL_PATH_SENTIMENT)
        else:
            raise FileNotFoundError(f"Sentiment model not found at: {MODEL_PATH_SENTIMENT}")
    return sentiment_model

def get_tokenizer():
    global tokenizer
    if tokenizer is None:
        if os.path.exists(TOKENIZER_PATH):
            with open(TOKENIZER_PATH, 'rb') as f:
                tokenizer = pickle.load(f)
        else:
            raise FileNotFoundError(f"Tokenizer not found at: {TOKENIZER_PATH}")
    return tokenizer

def get_car_model():
    global car_model
    if car_model is None:
        if os.path.exists(MODEL_PATH_CAR):
            car_model = joblib.load(MODEL_PATH_CAR)
        else:
            raise FileNotFoundError(f"Car model not found at: {MODEL_PATH_CAR}")
    return car_model

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# Use your manually defined BASE_
sentiment_model = None


def manual_pad_sequences(sequences, maxlen=100, padding='pre', value=0):
    import tensorflow as tf
    tf.config.threading.set_intra_op_parallelism_threads(1)
    # sequences is a list of lists (token IDs)
    padded = np.full((len(sequences), maxlen), value)

    for i, seq in enumerate(sequences):
        if len(seq) > maxlen:
            if padding == 'pre':
                seq = seq[-maxlen:]  # truncate from the front
            else:
                seq = seq[:maxlen]   # truncate from the end

        if padding == 'pre':
            padded[i, -len(seq):] = seq
        else:  # 'post' padding
            padded[i, :len(seq)] = seq
    return padded

@csrf_exempt
def send_password_reset_email(request, user):
    """
    Sends a password reset email to the user.

    Args:
        request: The Django request object (required for URL generation).
        user: The user object.
    """
    subject = "Password Reset Request"
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user.email]

    # Generate password reset token
    token = default_token_generator.make_token(user)
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))  # Encode the user's primary key

    # Construct the reset URL. Use reverse to get the URL.
    reset_url = request.build_absolute_uri(
        reverse("api:reset_password", kwargs={"uidb64": uidb64, "token": token}) # Change Here
    )

    context = {
        "user": user,
        "reset_url": reset_url,
    }

    # Construct the full path to the template.
    template_name = "password_reset_email.txt"
    # Check if the template exists
    template_path = os.path.join(settings.BASE_DIR, 'api/templates', template_name) # Ensure 'templates' dir exists
    if not os.path.exists(template_path):
        error_message = f"Template file not found: {template_path}"
        logger.error(error_message)
        return False  # Important: Return False if the template doesn't exist!

    try:
        text_content = render_to_string(template_name, context)
        send_mail(subject, text_content, from_email, recipient_list)
        logger.info(f"Password reset email sent to {user.email}")
        return True  # Indicate success
    except Exception as e:
        logger.error(f"Error sending password reset email: {e}")
        return False # Return false on error
    
@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = UserSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token, _ = Token.objects.create(user=user)
    return Response({
        'token': token.key,
    }, status=status.HTTP_201_CREATED)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(request, email=email, password=password)
    if user is not None:
        login(request, user)
        token, _ = Token.objects.get_or_create(user=user)
        return Response({
            # 'refresh': tokens['refresh'],
            'token': token.key,
        }, status=status.HTTP_200_OK)
    return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
@permission_classes([AllowAny])
def user_logout(request):
    logout(request)
    return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)

@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    """
    Retrieve or update the profile of the logged-in user.
    """
    logger.debug(f"Request User: {request.user}")
    try:
        JWTAuthentication().authenticate(request)  # Forcefully check the token.
    except (InvalidToken or TokenError or AuthenticationFailed) as e:
        logger.error(f"Token error: {e}")
        print(f"the error is {e}")
        return Response(
            {"detail": "Invalid or expired token.", "code": "token_invalid"},
            status=status.HTTP_401_UNAUTHORIZED,
        )
    user = request.user
    try:
        profile = User.objects.get(user=user)
        logger.debug(f"Profile found for user: {profile}")
    except User.DoesNotExist:
        profile = User(user=user)
        profile.save()
        logger.debug(f"Profile created for user: {profile}")

    if request.method == 'GET':
        serializer = ProfileSerializer(profile)
        logger.debug(f"GET request, Serialized data: {serializer.data}")
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.debug(f"PUT request, Serialized data: {serializer.data}")
            return Response(serializer.data)
        logger.error(f"PUT request, Serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@permission_classes([AllowAny])
def user_reset_password_request(request):
    """
    Endpoint to request a password reset.
    """
    email = request.data.get("email")
    if not email:
        return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        user = User.objects.get(email=email)
        email_sent = send_password_reset_email(request, user) # Pass request
        if email_sent:
            return Response(
                {"message": "Password reset email sent"}, status=status.HTTP_200_OK
            )
        else:
             return Response(
                {"error": "Failed to send password reset email"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
    else:
        return Response({"error": "Email not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST'])
@permission_classes([AllowAny])
def user_reset_password(request):
    email = request.data.get('email')
    new_password = request.data.get('new_password')
    token = request.data.get('token')
    if User.objects.filter(email=email).exists():
        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.save()
        return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
    return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([AllowAny])
def chat_list(request):
    user_chats = Chat.objects.filter(chatdetails__user=request.user)
    serializer = ChatSerializer(user_chats, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def chat_create(request):
    data = request.data.copy()
    data['sender'] = request.user.id
    serializer = ChatSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    chat = serializer.save()
    ChatDetails.objects.create(chat=chat, user=request.user)
    return Response(serializer.data, status=status.HTTP_201_CREATED)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def chat_detail(request, pk):
    chat = get_object_or_404(Chat, pk=pk)
    chat_serializer = ChatSerializer(chat)
    chat_details = ChatDetails.objects.filter(chat=chat)
    chat_details_serializer = ChatDetailSerializer(chat_details, many=True)
    return Response({
        'chat': chat_serializer.data,
        'chat_details': chat_details_serializer.data
    }, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def chat_users(request, pk):
    chat = get_object_or_404(Chat, pk=pk)
    users = User.objects.filter(chatdetails__chat=chat)
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

def chat_messages(request, chat_pk):
    if request.method == 'GET':
        return redirect('api:get_chat_messages', chat_pk)
    elif request.method == 'POST':
        return redirect('api:create_chat_messages', chat_pk)
    
@api_view(['GET']) 
def get_chat_messages(request, chat_pk):
    messages = Message.objects.filter(chat_id=chat_pk)
    serializer = MessageSerializer(messages, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(["POST"])
def create_chat_message(request, chat_pk):
    chat = get_object_or_404(Chat, pk=chat_pk)
    receiver = request.data.get('receiver')
    if receiver:
        receiver_user = User.objects.get(id=receiver)
    else: 
        return Response({'detail':"Receiver is required"}, status=status.HTTP_400_BAD_REQUEST)
    serializer = MessageSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    message = serializer.save(chat=chat, sender=request.user, receiver=receiver_user)
    return Response(serializer.data,status=status.HTTP_201_CREATED)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def notification_list(request):
    notifications = Notification.objects.filter(user=request.user).order_by("-created_at")
    serializer = NotificationSerializer(notifications, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def notification_mark_as_read(request, pk):
    notification = get_object_or_404(Notification, pk=pk, user=request.user)
    notification.is_read = True
    notification.save()
    return Response({'message': 'Notification marked as read'}, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def notification_mark_all_as_read(request):
    Notification.objects.filter(user=request.user).update(is_read=True)
    return Response({'message': 'All notifications marked as read'}, status=status.HTTP_200_OK)

@api_view(['GET']) 
def chat_category_list(request):
    categories = ChatCategory.objects.all()
    serializer = ChatCategorySerializer(categories, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET']) 
def announcement_list(request):
    announcements = Announcement.objects.all()
    serializer = AnnouncementSerializer(announcements, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
def predict_car_price(request):
    data = request.data

    # Required fields for API input
    try:
        year = float(data['year'])
        mileage = float(data['mileage'])
        engine_size = float(data['engine_size'])
        brand = data['brand']
        body = data['body']
        engine_type = data['engine_type']
        registration = data['registration']
    except (KeyError, ValueError):
        return Response({'error': 'Invalid input data'}, status=400)

    # Build a dict for one row
    row = {
        'Mileage': mileage,
        'EngineV': engine_size,
        'Year': year,
        # One-hot columns below, must match your training dummies
        f'Brand_{brand}': 1,
        f'Body_{body}': 1,
        f'Engine Type_{engine_type}': 1,
        'Registration_yes': 1 if registration == "yes" else 0
    }
    # Fill any missing columns with 0
    for col in FEATURE_ORDER:
        row.setdefault(col, 0)

    # Build DataFrame in the right column order
    input_df = pd.DataFrame([row], columns=FEATURE_ORDER)

    # Scale input
    input_scaled = scaler.transform(input_df)

    try:
        prediction_log = regression.predict(input_scaled)[0]
        predicted_price = float(10 ** prediction_log)
        return Response({'predicted_price': predicted_price}, status=200)
    except Exception as e:
        return Response({'error': str(e)}, status=500) 
    
@csrf_exempt
@api_view(["POST"])
def sentiment_api(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("Only POST requests allowed")

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    text = data.get('text', '').strip()
    if not text:
        return JsonResponse({"error": "No text provided"}, status=400)
    max_len = 20
    try:
        seq = tokenizer.texts_to_sequences([text])
        padded = manual_pad_sequences(seq, maxlen=max_len, padding='post', truncating='post')

        model = get_sentiment_model()
        preds = model.predict(padded)
        pred_class = int(np.argmax(preds))

        labels = {0: "NEGATIVE", 1: "POSITIVE", 2: "NEUTRAL", 3: "IRRELEVANT"}
        sentiment = labels.get(pred_class, "UNKNOWN")
        confidence = float(np.max(preds))

        return JsonResponse({
            "sentiment": sentiment,
            "confidence": round(confidence, 3)
        })

    except Exception as e:
        logging.error(f"Sentiment prediction error: {e}")
        return JsonResponse({"error": "Internal server error"}, status=500)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_emergencies(request):
    emergencies = Emergency.objects.all().order_by('-broadcast_at')
    serializer = EmergencySerializer(emergencies, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_emergency(request):
    serializer = EmergencySerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(created_by=request.user)
        return Response(serializer.data, status=201)
    return Response(serializer.errors, status=400)

@api_view(['GET', 'POST'])
def emergency(request):
    if request.method == 'GET':
        return list_emergencies(request)
    elif request.method == 'POST':
        return create_emergency(request)
    else:
        return Response({'error': 'Method not allowed'}, status=405)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_user_reports(request):
    reports = Report.objects.filter(user=request.user).order_by('-created_at')
    serializer = ReportSerializer(reports, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def submit_report(request):
    serializer = ReportSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(user=request.user)
        return Response(serializer.data, status=201)
    return Response(serializer.errors, status=400)

@api_view(['GET','POST'])
def report(request):
    if request.method == 'GET':
        return list_user_reports(request)
    elif request.method == 'POST':
        return submit_report(request)
    else:
        return Response({'error': 'Method not allowed'}, status=405)
@api_view(['GET'])   
def list_projects(request):
    projects = Project.objects.all().order_by('-start_date')
    serializer = ProjectSerializer(projects, many=True)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAdminUser])
def create_project(request):
    serializer = ProjectSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(created_by=request.user)
        return Response(serializer.data, status=201)
    else:
        return Response(serializer.errors, status=400)
@api_view(['GET', 'POST'])
def project(request):
    if request.method == 'GET':
        return list_projects(request)
    elif request.method == 'POST':
        return create_project(request)
    else:
        return Response({'error': 'Method not allowed'}, status=405)

def list_suggestions(request):
    suggestions = Suggestion.objects.all().order_by('-created_at')
    serializer = SuggestionSerializer(suggestions, many=True)
    return Response(serializer.data)

def create_suggestion(request):
    serializer = SuggestionSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(user=request.user)
        return Response(serializer.data, status=201)
    else:
        return Response(serializer.errors, status=400)
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def suggestion(request):
    if request.method == 'GET':
        return list_suggestions(request)
    elif request.method == 'POST':
        return create_suggestion(request)
    else:
        return Response({'error': 'Method not allowed'}, status=405)
    
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def dashboard(request):
    user = request.user

    latest_emergency = Emergency.objects.order_by('-broadcast_at')[:3]
    latest_report = Report.objects.filter(user=user).order_by('-created_at')[:3]
    latest_project = Project.objects.order_by('-start_date')[:3]
    latest_suggestion = Suggestion.objects.filter(user=user).order_by('-created_at').first()
    notifications = Notification.objects.filter(user=user).order_by('-created_at')[:2]
    unread_count = Notification.objects.filter(user=user, is_read=False).count()
    recent_announcements = Announcement.objects.order_by('-broadcast_at')[:2]

    dashboard = {}

    dashboard['greeting'] = f"Hello, {user.first_name}!"
    dashboard['user_name'] = user.email
    dashboard['emergency'] = EmergencySerializer(latest_emergency, many=True).data if latest_emergency else []
    dashboard['report'] = ReportSerializer(latest_report, many=True).data if latest_report else []
    dashboard['project'] = ProjectSerializer(latest_project, many=True).data if latest_project else []
    dashboard['suggestion'] = SuggestionSerializer(latest_suggestion).data if latest_suggestion else None
    dashboard['notifications'] = NotificationSerializer(notifications, many=True).data
    dashboard['unread_notifications'] = unread_count
    dashboard['announcements'] = AnnouncementSerializer(recent_announcements, many=True).data

    serializer = DashboardSerializer(dashboard, context={'request': request})
    return Response(serializer.data, status=status.HTTP_200_OK)