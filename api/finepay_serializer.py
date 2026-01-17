from rest_framework import serializers
from accounts.models import User

class FinePayUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'phone', 'profile_pic', 'password']
        
    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            phone=validated_data.get('phone', ''),
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
    def update(self, instance, validated_data):
        """Update user instance"""
        password = validated_data.pop('password', None) # gets the password, and removes it.
        for (key, value) in validated_data.items():
            setattr(instance, key, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance
