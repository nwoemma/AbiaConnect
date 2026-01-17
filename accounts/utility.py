from accounts.models import User

def generate_username(first_name, last_name):
    """Generate a unique username based on first and last name."""
    base_username = f"{first_name.lower()}.{last_name.lower()}"
    username = base_username
    counter = 1
    while User.objects.filter(username=username).exists():
        username = f"{base_username}{counter}"
        counter += 1
    return username