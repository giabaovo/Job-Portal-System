import cloudinary.uploader

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from django.db import transaction
from django.conf import settings

from authentication.models import User

from helpers import helper

from configs import variable_system as var_sys

class JobSeekerRegisterSerializer(serializers.ModelSerializer):

    email = serializers.EmailField(max_length=100, required=True, 
                                   validators=[UniqueValidator(queryset=User.objects.all(), message='Email already exists')])
    full_name = serializers.CharField(max_length=100, required=True)
    password = serializers.CharField(max_length=100, required=True)
    confirm_password = serializers.CharField(max_length=100, required=True)


    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'The password and confirmation password do not match'})
        return attrs

    def create(self, validated_data):
        try:
            with transaction.atomic():
                validated_data.pop('confirm_password')

                user = User.objects.create_user_with_role(**validated_data, role_name=var_sys.JOB_SEEKER, is_active=False)
                return user
        except Exception as ex:
            helper.print_log_error('Create user in JobSeekerRegisterSerializer', ex)
            return None

    class Meta:
        model = User
        fields = ['email', 'full_name', 'password', 'confirm_password']

class EmployerRegisterSerializer(serializers.ModelSerializer):

    email = serializers.EmailField(max_length=100, required=True, 
                                   validators=[UniqueValidator(queryset=User.objects.all(), message='Email already exists')])
    full_name = serializers.CharField(max_length=100, required=True)
    password = serializers.CharField(max_length=100, required=True)
    confirm_password = serializers.CharField(max_length=100, required=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'The password and confirmation password do not match'})
        return attrs
    
    def create(self, validated_data):
        try:
            with transaction.atomic():
                validated_data.pop('confirm_password')

                user = User.objects.create_user_with_role(**validated_data, role_name=var_sys.EMPLOYER, has_company=True, is_active=False)

                return user
        except Exception as ex:
            helper.print_log_error('Create user in EmployerRegisterSerializer', ex)
            return None

    class Meta:
        model = User
        fields = ['email', 'full_name', 'password', 'confirm_password']

class CheckCredsSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, max_length=100)
    role_name = serializers.CharField(max_length=100, allow_null=True, allow_blank=True)

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True, max_length=100)


class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True, max_length=100)
    confirm_password = serializers.CharField(required=True, max_length=100)
    token = serializers.CharField(required=True)

    def __init__(self, *args, **kwargs):

        fields = kwargs.pop('fields', None)

        super().__init__(*args, **kwargs)

        if fields:
            allowed = set(fields)
            existing = set(self.fields)
            for field_name in (existing - allowed):
                self.fields.pop(field_name)

    def validate(self, attrs):
        new_password = attrs['new_password']
        confirm_password = attrs['confirm_password']
        token = attrs['token']

        if new_password != confirm_password:
            raise serializers.ValidationError({'confirm_password': 'The password and confirmation password do not match'})
        
        if not token:
            raise serializers.ValidationError({'token': 'Token is required'})

        return attrs
    

class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, max_length=100)
    new_password = serializers.CharField(required=True, max_length=100)
    confirm_password = serializers.CharField(required=True, max_length=100)

    def validate(self, attrs):
        user = self.context.get('user')

        old_password = attrs['old_password']
        new_password = attrs['new_password']
        confirm_password = attrs['confirm_password']

        if new_password != confirm_password:
            raise serializers.ValidationError({'confirm_password': 'The password and confirmation password do not match'})

        if not user.check_password(old_password):
            raise serializers.ValidationError({'old_password': 'The old password is not correct'})

        return attrs
    
    def update(self, instance, validated_data):
        instance.set_password(validated_data['new_password'])
        instance.save()
        return instance
    

class AvatarSerializer(serializers.ModelSerializer):
    file = serializers.FileField(required=True, write_only=True)
    avatar_url = serializers.CharField(required=False, max_length=300, read_only=True)

    def update(self, user, validated_data):
        file = validated_data.pop('file')

        try:
            avatar_upload_result = cloudinary.uploader.upload(file=file, 
                                                              folder=settings.CLOUDINARY_DIRECTORY['avatar'], 
                                                              public_id=user.id)
            
            avatar_public_id = avatar_upload_result.get('public_id')
        except:
            return None
        else:
            avatar_url = avatar_upload_result.get('secure_url')

            user.avatar_url = avatar_url
            user.avatar_public_id = avatar_public_id
            user.save()

            return user

    class Meta:
        model = User
        fields = ['file', 'avatar_url']