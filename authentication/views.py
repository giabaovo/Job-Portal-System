from rest_framework import status
from rest_framework.decorators import api_view, permission_classes

from authentication.serializers import (
    JobSeekerRegisterSerializer
)

from helpers import helper

from configs import variable_response as var_res

@api_view(http_method_names=['post'])
def job_seeker_register(request):
    data = request.data
    serializer = JobSeekerRegisterSerializer(data=data)
    if not serializer.is_valid():
        return var_res.response_data(status=status.HTTP_400_BAD_REQUEST, errors=serializer.errors)
    
    try:
        user = serializer.save()
        if user:
            # Sending Verify Email
            helper.send_verify_email(request, user)
    except Exception as ex:
        helper.print_log_error('job_seeker_register', ex)
        return var_res.response_data(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return var_res.response_data(status=status.HTTP_201_CREATED)