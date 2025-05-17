from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from accounts.models import User
from django.utils import timezone
from .form import RegisterForm
from django.core.mail import send_mail
import random

def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            # You can customize user save behavior here
            user.save()
            return redirect('login')
        else:
            errors = form.errors
            return render(request, 'register.html', {'form': form, 'errors': errors})
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})

def login_user(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})
    else:
        return render(request, 'login.htnl')
    
def logout_user(request):
    logout(request)
    return redirect('login' , {'message': 'You have been logged out.'})