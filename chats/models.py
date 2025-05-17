from django.db import models
from accounts.models import User

class Chat(models.Model):
    sender = models.ForeignKey(User, related_name='sent_chats', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_chats', on_delete=models.CASCADE)
    message = models.TextField()
    audio = models.FileField(upload_to='chats/audios/', blank=True, null=True)
    video = models.FileField(upload_to='chats/videos/', blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_seen = models.BooleanField(default=False) 

    def __str__(self):
        return f"{self.sender.email} to {self.receiver.email}: {self.message[:20]}..."
class NotifyChat(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='notify_chats'
    )
    chat = models.ForeignKey(
        Chat, on_delete=models.CASCADE, related_name='notify_chats'
    )
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"NotifyChat for {self.user.email} in Chat {self.chat.id}, read={self.is_read}"
    
class Message(models.Model):
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages', default=True)  # 🔥 ADD THIS
    text = models.TextField(blank=True, null=True)
    audio = models.FileField(upload_to='audio/', blank=True, null=True)
    video = models.FileField(upload_to='video/', blank=True, null=True)
    image = models.ImageField(upload_to='images/', blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

class Category(models.TextChoices):
    EMERGENCY = 'EM', 'Emergency'
    SUGGESTION = 'SG', 'Suggestion'
    PROJECT_FEEDBACK = 'PF', 'Project Feedback'
    HUMAN_DEVELOPMENT = 'HD', 'Human Development'
    
class Conversion(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='conversions')
    message = models.TextField(blank=True, null=True)
    media = models.FileField(upload_to='chat_media/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"Conversion by {self.user.username} at {self.created_at}"
class ChatDetails(models.Model):
    chat_detail_id = models.AutoField(primary_key=True)
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    joined_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} in {self.chat.chat_name}"
    
class ChatCategory(models.Model):
    category_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    description = models.TextField()
    
    def __str__(self):
        return self.name