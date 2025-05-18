import logging
import os
import ssl
import certifi
import numpy as np
import tensorflow as tf
from keras.models import load_model

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
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError, AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken

from keras.preprocessing.sequence import pad_sequences
import pickle
from accounts.models import User, Profile
from chats.models import Chat, Conversion, ChatDetails, ChatCategory, Message
from news.models import Notification, Announcement

from .serializers import (
    AnnouncementSerializer,
    ChatCategorySerializer,
    ChatDetailSerializer,
    ChatSerializer,
    MessageSerializer,
    NotificationSerializer,
    ProfileSerializer,
    UserSerializer,
)


logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ssl_context = ssl.create_default_context(cafile=certifi.where())
MODEL_PATH_CAR = os.path.join(settings.BASE_DIR, 'ml_model', 'car_prices.h5')
MODEL_PATH_NLP = os.path.join(settings.BASE_DIR, 'ml_model', 'NLP(Deep_Learning).h5')
TOKENIZER_PATH = os.path.join(settings.BASE_DIR, 'ml_model', 'tokenizer.pkl')

car_model = None
sentiment_model = None
tokenizer = None

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
            car_model = load_model(MODEL_PATH_CAR)
        else:
            raise FileNotFoundError(f"ML model not found at: {MODEL_PATH_CAR}")
    return car_model
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


tf.config.threading.set_intra_op_parallelism_threads(1)
tf.config.threading.set_inter_op_parallelism_threads(1)
# Use your manually defined BASE_
sentiment_model = None

def get_sentiment_model():
    global sentiment_model
    if sentiment_model is None:
        if os.path.exists(MODEL_PATH_NLP):
            sentiment_model = load_model(MODEL_PATH_NLP)
        else:
            raise FileNotFoundError(f"Sentiment model not found at: {MODEL_PATH_NLP}")
    return sentiment_model

@csrf_exempt
def sentiment_api(request):
    print("File exists:", os.path.exists(MODEL_PATH_CAR))
    print("File exists:", os.path.exists(MODEL_PATH_NLP))
    print("File exists:", os.path.exists(TOKENIZER_PATH))
    if request.method == 'POST':
        message = request.POST.get('message')
        if not message:
            return JsonResponse({'error': 'No message provided'}, status=400)

        # Convert message to padded sequence
        tokenizer_instance = get_tokenizer()
        sequence = tokenizer.texts_to_sequences([message])
        padded = pad_sequences(sequence, maxlen=100)

        # Predict sentiment
        model = get_sentiment_model()
        prediction = sentiment_model.predict(padded)[0][0]

        # Label based on threshold
        sentiment = 'Positive' if prediction >= 0.5 else 'Negative'

        return JsonResponse({
            'message': message,
            'sentiment': sentiment,
            'score': float(prediction)
        })

    return JsonResponse({'error': 'Invalid request method'}, status=405)



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
    Profile.objects.create(user=user)
    tokens = get_tokens_for_user(user)
    return Response({
        'refresh': tokens['refresh'],
        'access': tokens['access'],
    }, status=status.HTTP_201_CREATED)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(request, email=email, password=password)
    if user is not None:
        login(request, user)
        tokens = get_tokens_for_user(user)
        return Response({
            'refresh': tokens['refresh'],
            'access': tokens['access'],
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
        profile = Profile.objects.get(user=user)
        logger.debug(f"Profile found for user: {profile}")
    except Profile.DoesNotExist:
        profile = Profile(user=user)
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
    notifications = Notification.objects.filter(user=request.user)
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
@permission_classes([AllowAny]) # Adjust permissions as needed
def chat_category_list(request):
    categories = ChatCategory.objects.all()
    serializer = ChatCategorySerializer(categories, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([AllowAny])  # Adjust permissions as needed
def announcement_list(request):
    announcements = Announcement.objects.all()
    serializer = AnnouncementSerializer(announcements, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

# car_model = None
# def get_car_model():
#     global car_model
#     if car_model is None:
#         if os.path.exists(MODEL_PATH_CAR):
#             car_model = load_model(MODEL_PATH_CAR)
#         else:
#             raise FileNotFoundError(f"Car price model not found at: {MODEL_PATH_CAR}")
#     return car_model



# model_1 = None
# def get_sentiment_model():
#     global model_1
#     if model_1 is None:
#         if os.path.exists(MODEL_PATH_SENTIMENT):
#             model_1 = load_model(MODEL_PATH_SENTIMENT)
#         else:
#             raise FileNotFoundError(f"Sentiment model not found at: {MODEL_PATH_SENTIMENT}")
#     return model_1

# @api_view(['POST'])
# @permission_classes([AllowAny])
# def predict_car_price(request):
#     data = request.data

#     try:
#         year = float(data['year'])
#         mileage = float(data['mileage'])
#         engine_size = float(data['engine_size'])
#     except (KeyError, ValueError):
#         return Response({'error': 'Invalid input data'}, status=400)

#     # Prepare the input as a 2D NumPy array
#     input_features = np.array([[year, mileage, engine_size]])

#     try:
#         model = get_car_model()
#         prediction = model.predict(input_features)

#         # Assuming the model returns a single value
#         predicted_price = float(prediction[0])
#         return Response({'predicted_price': predicted_price}, status=200)
#     except Exception as e:
#         return Response({'error': str(e)}, status=500)
    
# MODEL_PATH_SENTIMENT = os.path.join(BASE_DIR, 'ml_model', 'sentiment_model.h5')
# model_1 = None

# @csrf_exempt
# @api_view(["POST"])
# def sentiment_api(request):
#     if request.method != 'POST':
#         return HttpResponseBadRequest("Only POST requests allowed")

#     try:
#         data = json.loads(request.body)
#     except json.JSONDecodeError:
#         return JsonResponse({"error": "Invalid JSON"}, status=400)

#     text = data.get('text', '').strip()
#     if not text:
#         return JsonResponse({"error": "No text provided"}, status=400)

#     try:
#         seq = tokenizer.texts_to_sequences([text])
#         padded = pad_sequences(seq, maxlen=max_len, padding='post', truncating='post')

#         preds = model_1.predict(padded)  # make sure model_1 is lazily loaded too, if needed
#         pred_class = np.argmax(preds)

#         labels = {0: "NEGATIVE", 1: "POSITIVE", 2: "NEUTRAL", 3: "IRRELEVANT"}
#         sentiment = labels.get(pred_class, "UNKNOWN")
#         confidence = float(np.max(preds))

#         return JsonResponse({"sentiment": sentiment, "confidence": confidence})

#     except Exception as e:
#         logger.error(f"Sentiment prediction error: {e}")
#         return JsonResponse({"error": "Internal server error"}, status=500)
