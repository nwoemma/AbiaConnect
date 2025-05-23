# urls.py
from django.urls import path
from .views import home_view  # adjust the import path based on where you put the view

urlpatterns = [
    path('', home_view, name='home'),
    # ... other paths
]
