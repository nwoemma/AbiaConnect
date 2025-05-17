from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
import uuid
# Create your models here.

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and return a regular user with an email and password.
        """
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and return a superuser with an email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        
        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15, unique=True, blank=True, null=True)
    profile_pic = models.ImageField(upload_to='profile_pics', blank=True, null=True)
    password_reset_token = models.CharField(max_length=255, blank=True, null=True)

    SEX_CHOICES = (
        ('male', 'Male'),
        ('female', 'Female'),
    )
    sex = models.CharField(max_length=10, choices=SEX_CHOICES, blank=True, null=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    
    REQUIRED_FIELDS = []
    
    USER_TYPE_CHOICES = (
        ('citizen', 'Citizen'),
        ('govt_official', 'Government Official'),
        ('call_agent', 'Call Center Agent'),
        ('admin', 'Admin'),
    )
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, default='citizen')

    preferred_language = models.CharField(max_length=30, blank=True, null=True)

    ENTRY_POINT_CHOICES = (
        ('mobile_app', 'Mobile App'),
        ('whatsapp', 'WhatsApp'),
        ('ussd', 'USSD'),
        ('web', 'Web'),
    )
    entry_point = models.CharField(max_length=20, choices=ENTRY_POINT_CHOICES, blank=True, null=True)

    location = models.CharField(max_length=100, blank=True, null=True)
    
    def __str__(self):
        return self.email
    def save(self, *args, **kwargs):
        if not self.username:
            self.username = str(uuid.uuid4())[:30]
        super().save(*args, **kwargs)
        
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    preferred_language = models.CharField(max_length=10, default='en')
    bio = models.CharField(max_length=90,default='bio')
    location = models.CharField(max_length=50,null=True)
