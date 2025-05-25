from django.urls import path
from . import views
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView # Import TokenRefreshView

app_name = 'api'


urlpatterns = [
    # User Management
    path('users/register/', views.register, name='register'),
    path('users/login/', views.login_user, name='login'),
    path('users/logout/', views.user_logout, name='logout'),
    path('users/profile/', views.user_profile, name='profile'),
    path('users/reset-password-request/', views.user_reset_password_request, name='password_request_reset'),
    path('users/reset-password/<str:uidb64>/<str:token>/', views.user_reset_password, name='reset_password'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Chat Management
    path('chats/', views.chat_list, name='chat_list'),
    path('chats/create/', views.chat_create, name='chat_create'),
    path('chats/<int:pk>/', views.chat_detail, name='chat_detail'),
    path('chats/<int:pk>/users/', views.chat_users, name='chat_users'),
    path('get_chat_messages/<int:chat_pk>/', views.get_chat_messages, name='get_chat_messages'),
    path('create_chat_messages/<int:chat_pk>/',views.create_chat_message, name="create_chat_messages"),

    # Notification Management
    path('notifications/', views.notification_list, name='notification_list'),
    path('notifications/<int:pk>/mark-as-read/', views.notification_mark_as_read, name='notification_mark_as_read'),
    path('notifications/mark-all-as-read/', views.notification_mark_all_as_read, name='notification_mark_all_as_read'),

    # Chat Category and Announcement
    path('chatcategories/', views.chat_category_list, name='chat_category_list'),
    path('announcements/', views.announcement_list, name='announcement_list'),
    path('sentiment/', views.sentiment_api,name="sentiment"),
    path('predict/', views.predict_car_price, name="predict")
]
