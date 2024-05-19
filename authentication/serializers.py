from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from django.db import transaction

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