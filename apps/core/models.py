import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ('analyst', 'Analyst'),
        ('admin', 'Admin'),
        ('viewer', 'Viewer'),
    )

    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255, blank=True)
    company = models.CharField(max_length=255, blank=True, null=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)
    api_key = models.CharField(max_length=255, unique=True, blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = str(uuid.uuid4())
        super().save(*args, **kwargs)


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    location = models.CharField(max_length=100, blank=True)
    
    def __str__(self):
        return f'{self.user.email} Profile'


class UserSetting(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='settings')
    theme = models.CharField(max_length=20, default='dark', choices=(('light', 'Light'), ('dark', 'Dark')))
    enable_ai_remediation = models.BooleanField(default=True)
    webhook_url = models.URLField(blank=True, null=True)
    
    # Tool Integration
    zap_api_key = models.CharField(max_length=255, blank=True)
    zap_proxy_url = models.CharField(max_length=255, default='http://localhost:8080')
    
    # Notifications
    email_notifications = models.BooleanField(default=True)
    scan_complete_alerts = models.BooleanField(default=True)

    def __str__(self):
        return f'{self.user.email} Settings'


@receiver(post_save, sender=User)
def create_or_update_user_related(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
        UserSetting.objects.create(user=instance)
    else:
        try:
            instance.profile.save()
        except UserProfile.DoesNotExist:
            UserProfile.objects.create(user=instance)
        
        try:
            instance.settings.save()
        except UserSetting.DoesNotExist:
            UserSetting.objects.create(user=instance)
