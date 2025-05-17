from django import forms
from .models import User

class RegisterForm(forms.ModelForm):
    firstname = forms.CharField(max_length=30)
    lastname = forms.CharField(max_length=30)
    email = forms.EmailField()
    phone = forms.CharField(max_length=15)
    profile_picture = forms.ImageField(required=False)
    password = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput, label='Confirm Password')
    LOCAL_GOVERNMENT_CHOICES = [
        ('aba_north',"Aba North"),
        ('aba_south',"Aba South"),
        ('abia_central',"Abia Central"),
        ('abia_south',"Abia South"),
        ('abia_north',"Abia North"),
        ('isiala_ngwa_north',"Isiala Ngwa North"),
        ('isiala_ngwa_south',"Isiala Ngwa South"),
        ('obingwa',"Obingwa"),
        ('osisioma_ngwa',"Osisioma Ngwa"),
        ('ukwuanum',"Ukwuanum"),
        ('bende',"Bende"),
        ('ohafia',"Ohafia"),
        ('umuahia',"Umuahia"),
        ('arochukwu',"Arochukwu"),
        ('isukwuato',"Isukwuato"),
        ('item',"Item"),
        ('ikawere',"Ikawere"),
        ('obingwa',"Obingwa"),
        ('osisioma_ngwa',"Osisioma Ngwa"),
        ('ukwuanum',"Ukwuanum"),
        ('umuahia_north',"Umuahia North"),
        ('umuahia_south',"Umuahia South"),
    ]
    local_government = forms.ChoiceField(choices=LOCAL_GOVERNMENT_CHOICES)
    class Meta:
        model = User
        fields = ['firstname', 'lastname','email', 'phone', 'password', 'password2', 'local_government']
    
    def clean_email(self):
        email = self.changed_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already exists.")
        return email
    