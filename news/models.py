from django.db import models
from accounts.models import User

class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=255)
    messages = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
class Announcement(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    broadcast_at = models.DateTimeField(auto_now_add=True)  # Automatically set the date and time when the announcement is created
    picture = models.ImageField(upload_to='announcements/', blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)#should the announcement creator be deleted, the announcement will still exist?
    def __str__(self):
        return self.title

class Emergency(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    broadcast_at = models.DateTimeField(auto_now_add=True)  # Automatically set the date and time when the alert is created
    picture = models.ImageField(upload_to='emergency_alerts/', blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)  # Should the alert creator be deleted, the alert will still exist?
    def __str__(self):
        return self.title
    
class Report(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    title = models.CharField(max_length=255)
    description = models.TextField()
    location = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)
    def __str__(self):
        return self.title
    

class Project(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    start_date = models.DateTimeField(auto_now_add=True)
    end_date = models.DateTimeField(blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='projects')  
    def __str__(self):
        return self.name
    
class Suggestion(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='suggestions')
    title = models.CharField(max_length=255)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return self.title