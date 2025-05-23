# urls.py
from django.urls import path
from .views import home_chat # adjust the import path based on where you put the view

urlpatterns = [
    path('', home_chat, name='home'),
    # ... other paths
]
