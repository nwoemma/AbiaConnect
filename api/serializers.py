from rest_framework import serializers
from accounts.models import User, Profile
from news.models import  Notification, Announcement
from chats.models import Chat,Message,ChatDetails,ChatCategory

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'is_staff']
        read_only_fields = ['id', 'is_staff']
    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),  # Handle optional fields
            last_name=validated_data.get('last_name', ''),
            username=validated_data['username']
            #password=validated_data['password'], #DO NOT DO THIS
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


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['preferred_language']

class MessageSerializer(serializers.ModelSerializer):
    receiver = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), required=False)

    class Meta:
        model = Message
        fields = "__all__"
        read_only_fields = ['id', 'timestamp', 'sender']

class ChatSerializer(serializers.ModelSerializer):
    messages = MessageSerializer(many=True, read_only=True)
    class Meta:
        model = Chat
        fields = "__all__"
        read_only_fields = ['id', 'created_at', 'messages', 'user']

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = "__all__"
        read_only_fields = ['id', 'created_at']

class AnnouncementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Announcement
        fields = "__all__"
        read_only_fields = ['id', 'created_by']

class ChatDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatDetails
        fields = "__all__"
        

class ChatCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatCategory
        fields = "__all__"