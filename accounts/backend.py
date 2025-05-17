from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

class EmailBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None):
        print(f"Authenticating user with email: {email}")
        try:
            user = get_user_model().objects.get(email=email)
            print(f"User found: {user.email}")
            print(f'User password:{user.password}')
            if user.check_password(password):
                print("Password is correct")
                return user
            else:
                print(f"Password {password} is incorrect")
        except get_user_model().DoesNotExist:
            print("User not found")
            return None