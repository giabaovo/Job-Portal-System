from rest_framework import status
from rest_framework.response import Response

def data_response(data, errors):
    return {
        'data': data,
        'errors': errors
    }

def response_data(status=status.HTTP_200_OK, errors=None, data=None):
    if errors is None:
        errors = {}
    return Response(status=status, data=data_response(data=data, errors=errors))