from configs import variable_system as var_sys

from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

class AuthBaseModel(models.Model):
    class Meta:
        abstract = True

    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)

class UserManager(BaseUserManager):
    def create_user(self, email, full_name, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        
        if not full_name:
            raise ValueError('Full name is required')
        
        user = self.model(email=self.normalize_email(email), full_name=full_name, **extra_fields)
        user.set_password(password)
        user.save()

        return user 

    def create_superuser(self, email, full_name, password=None, **extra_fields):
        if not password:
            raise ValueError('Password is required')
        
        user = self.create_user_with_role(email=email, full_name=full_name, role_name=var_sys.ADMIN, 
                                          password=password, is_staff=True, is_superuser=True, 
                                          is_active=True, is_verify_email=True)

        return user

    def create_user_with_role(self, email, full_name, role_name, password=None, **extra_fields):
        if not role_name:
            raise ValueError('Role name is required')
        
        user = self.create_user(email=email, full_name=full_name, password=password, **extra_fields)
        user.role_name = role_name
        user.save()

        return user
        

class User(AbstractUser, AuthBaseModel):
    username = None
    first_name = None
    last_name = None
    date_joined = None

    full_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100, unique=True, db_index=True)
    avatar_url = models.URLField(max_length=300, default=var_sys.AVATAR_DEFAULT['AVATAR'])
    avatar_public_id = models.CharField(max_length=300, null=True)
    email_notification_active = models.BooleanField(default=True)
    has_company = models.BooleanField(default=False)
    is_verify_email = models.BooleanField(default=False)

    role_name = models.CharField(max_length=10, choices=var_sys.ROLE_CHOICES, default=var_sys.JOB_SEEKER)

    class Meta:
        db_table = 'job_portal_system_authenticate_user'
        verbose_name_plural = 'Users'

    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name']
