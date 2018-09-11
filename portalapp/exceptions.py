from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException

class ProfileDoesNotExist(APIException):
    status_code = 400
    default_detail = 'The requested profile does not exist.'

class PortalIsDown(APIException):
    status_code = 400
    default_detail = 'Portal has some issue.'

class UpdateFailException(APIException):
    status_code = 400
    default_detail = "Queryset has multiple result"

class UserDoesNotExist(APIException):
    status_code = 400
    default_detail = 'No User Found.'


def core_exception_handler(exc, context):
    response = exception_handler(exc, context)
    handlers = {
        'ProfileDoesNotExist': _handle_generic_error,
        'ValidationError': _handle_generic_error
    }
    exception_class = exc.__class__.__name__

    if exception_class in handlers:
        return handlers[exception_class](exc, context, response)

    return response

def _handle_generic_error(exc, context, response):
    response.data = {
        'errors': response.data
    }

    return response

