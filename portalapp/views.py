
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters
from django.utils.translation import ugettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import RetrieveUpdateAPIView, CreateAPIView
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.decorators import api_view

from .exceptions import (ProfileDoesNotExist,
                         PortalIsDown,
                         UpdateFailException)
from .models import (
    Profile,
    Project,
    User,
    Basic,
    Experience,
    Education,
    Skill,
    Test, MyTest, Question)
from .permissions import ModelObjectPermission, AdminTypePermission
from .renderers import (ProfileJSONRenderer, UserJSONRenderer)
from .serializers import (
    ProjectSerializer, ProfileSerializer,
    BasicSerializer, ExperienceSerializer,
    EducationSerializer, SkillSerializer,
    TestSerializer, RegistrationSerializer,
    LoginSerializer, UserSerializer, MyTestSerializer,
    QuestionSerializer, ChangePasswordSerializer,
    PasswordResetSerializer, PasswordResetConfirmSerializer)

import logging
logger = logging.getLogger("info_logger")

sensitive_post_parameters_m = method_decorator(
    sensitive_post_parameters(
        'password', 'old_password', 'new_password1', 'new_password2'
    )
)

class RegistrationAPIView(APIView):
    # Allow any user (authenticated or not) to hit this endpoint.
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer
    renderer_classes = (UserJSONRenderer,)

    def post(self, request):
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = {"username": username, "email": email, "password": password}
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class LogoutAPIView(APIView):

    def get(self, request):
        pass


class LoginAPIView(APIView):
    permission_classes = (AllowAny,)
    renderer_classes = (UserJSONRenderer,)
    serializer_class = LoginSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class UpdatePassword(APIView):
    """
    An endpoint for changing password.
    """
    permission_classes = (IsAuthenticated, )

    def get_object(self, queryset=None):
        return self.request.user

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            old_password = serializer.data.get("old_password")
            if not self.object.check_password(old_password):
                return Response({"old_password": ["Wrong password."]},
                                status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            return Response(status=status.HTTP_204_NO_CONTENT)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.template import loader
from django.core.mail import EmailMultiAlternatives
from django.conf import settings

UserModel = get_user_model()

def make_token(user):
    token = default_token_generator.make_token(user)
    print("Token created for password reset: {} - user: {}".format(token, user))
    return token



def send_mail(context, from_email, to_email,
              subject_template_name = "password_reset_subject.txt", email_template_name= "password_reset_email.html",
              html_email_template_name=None):
        """
        Send a django.core.mail.EmailMultiAlternatives to `to_email`.
        """
        subject = loader.render_to_string(subject_template_name, context)
        # Email subject *must not* contain newlines
        subject = ''.join(subject.splitlines())
        body = loader.render_to_string(email_template_name, context)

        email_message = EmailMultiAlternatives(subject, body, from_email, [to_email])
        if html_email_template_name is not None:
            html_email = loader.render_to_string(html_email_template_name, context)
            email_message.attach_alternative(html_email, 'text/html')

        email_message.send()

class ForgotPassword(GenericAPIView):
    permission_classes = (AllowAny,)

    def get_users(self, email):
        active_users = UserModel._default_manager.filter(**{
            '%s__iexact' % UserModel.get_email_field_name(): email,
            'is_active': True,
        })
        return active_users

    def post(self, request, *args, **kwargs):
        use_https = False #TODO
        data = self.request.POST
        email = data.get('email')
        if not email:
            return Response({"Error": "Email not provided"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            user = self.get_users(email).first()
            host = request.get_host()
            domain = host.split(":")[0]
            context = {
                'email': email,
                'domain': domain,
                'site_name': domain, #site_name,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                'user': user,
                'token': make_token(user),
                'protocol': 'https' if use_https else 'http',
            }
            print("context: {}".format(context))
            send_mail(context, settings.EMAIL_HOST_USER,email)
            return Response({"context": user.email}, status=status.HTTP_200_OK)


def decode_token(uid,token):
    token_generator = default_token_generator
    try:
        user = UserModel._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
        user = None

    if user is not None and token_generator.check_token(user, token):
        validlink = True
    else:
        validlink = False
    return validlink, user


@api_view(["GET"])
def password_reset_confirm(request, uidb64,token=None):
    fulltoken = "{}-{}".format(uidb64, token)
    uidb64, token = fulltoken.split("-",1)
    uid = urlsafe_base64_decode(uidb64).decode()
    validlink, user = decode_token(uid, token)
    return Response({"validlink": validlink, "user": uid})


from .serializers import ResetPasswordSerializer
class NewPasswordUpdate(GenericAPIView):

    def post(self, request, *args, **kwargs):
        data = request.POST
        serializer = ResetPasswordSerializer(data=data)
        if not serializer.is_valid():
            return Response({"Error": "Recheck Input Data"}, status=status.HTTP_400_BAD_REQUEST)

        if serializer.data.get('new_password1')!=serializer.data.get('new_password2'):
            return Response({"Error": "new_password1 and new_password2 not matching!"}, status=status.HTTP_403_FORBIDDEN)

        uid = urlsafe_base64_decode(serializer.data.get('uid')).decode()
        valid, user = decode_token(uid, serializer.data.get('token'))
        if not valid:
            return Response({"Error": "Link provided is not valid."}, status=status.HTTP_403_FORBIDDEN)

        user.set_password(serializer.data.get("new_password1"))
        user.save()
        return Response(
            {"detail": _("Password has been reset with the new password.")}
        )

# # Have to call these functions for Gmail Authetication
# from portal import settings
# from django.contrib.auth import login, authenticate
# from rest_framework.decorators import api_view
# from django.shortcuts import redirect
# from social_django.models import UserSocialAuth
# import requests
# import json

# @api_view(["GET"])
# def set_request_user(request):
#     username = request.user.username
#     data = {}
#     if not username and '_auth_user_id' in request.session:
#         user_obj = User.objects.filter(id=request.session['_auth_user_id'])[0]
#         # request.user = user_obj
#         uid = user_obj.email
#         uid = "deepakumar0931@gmail.com"
#         user_social_auth = UserSocialAuth.objects.get_social_auth('google-oauth2', uid)
#         access_token = user_social_auth.extra_data.get('access_token')
#         token_type = user_social_auth.extra_data.get('token_type')
#         data = {"access_token": access_token, "token_type": token_type}
#         headers= {"Content-Type" : "application/json"}
#         r = requests.post("http://www.example.com:8000/auth/convert-token/", data=data, headers=headers)
#         print(r.status_code)
#     return Response({})

def query_filter(q_param):
    search_filter = {}
    for ftr in q_param:
        if "," in q_param[ftr]:
            new_key = "{}__in".format(ftr)
            search_filter[new_key] = [int(id) if id.isdigit() else id for id in q_param[ftr].split(",")]
        else:
            search_filter[ftr] = q_param[ftr]
    print(search_filter)
    return search_filter


class UserRetrieveUpdateAPIView(RetrieveUpdateDestroyAPIView, CreateAPIView, ModelObjectPermission):
    permission_classes = (IsAuthenticated)
    renderer_classes = (UserJSONRenderer,)
    serializer_class = UserSerializer

    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        email = request.user.email
        userObj = User.objects.get(email=email)

        self.has_change_permission(request, userObj)

        serializer_data = {
            'username': request.POST.get('username')
        }

        serializer = self.serializer_class(
            userObj, data=serializer_data, partial=True
        )

        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)

    def delete(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            user = User.objects.get(email=request.user.email)
            self.has_delete_permission(request, user)
            user.delete()
        else:
            raise PermissionDenied
        msg = {"Message": "User with Email " + user.email + " is deleted successfully"}
        return Response(msg, status=status.HTTP_200_OK)


class ProfileRetrieveAPIView(RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    renderer_classes = (ProfileJSONRenderer,)
    serializer_class = ProfileSerializer

    def get_queryset(self):
        return Profile.objects.all(user=self.request.user)

    def get(self, request, *args, **kwargs):
        try:
            user_email = request.user.email
            if request.GET.get('email'):
                user_email = request.GET.get('email')

            profile = Profile.objects.select_related('user').get(user__email=user_email).order_by('id')
            serializer = self.serializer_class(profile)
        except ProfileDoesNotExist:
            raise ProfileDoesNotExist
        except:
            raise PortalIsDown


        return Response(serializer.data, status=status.HTTP_200_OK)


class ProjectCreateAPIView(CreateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ProjectSerializer

    def post(self, request, *args, **kwargs):
        post_data = request.data.copy()
        post_data['profile_id'] = request.user.profile.id
        serializer = self.serializer_class(data=post_data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProjectRetrieveUpdateDestroyAPIView(RetrieveUpdateDestroyAPIView, ModelObjectPermission):
    permission_classes = (IsAuthenticated,)
    serializer_class = ProjectSerializer

    def get_queryset(self):
        q_param = self.request.query_params
        search_filter = query_filter(q_param)
        email = q_param.get('email')
        if email:
            queryset = Project.objects.filter(profile__user__email=email).order_by('id')
        elif search_filter:
            queryset = Project.objects.filter(**search_filter).order_by('id')
        else:
            queryset = Project.objects.filter(profile=self.request.user.profile).order_by('id')
        return queryset

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            projects = self.get_queryset()
            projects = ProjectSerializer(projects, many=True)
            return Response(projects.data, status=status.HTTP_200_OK)
        raise PermissionDenied

    def put(self, request, *args, **kwargs):
        project = self.get_queryset()
        if len(project) >1:
            raise UpdateFailException
        project = project.first()
        # Permission check
        self.has_change_permission(request, project.profile.user)
        data = request.data
        serializer = self.serializer_class(project, data=data, partial=True)
        if serializer.is_valid(raise_exception=True):
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"Error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, *args, **kwargs):
        project = self.get_queryset()
        if len(project) >1:
            raise UpdateFailException
        project = project.first()
        # Permission check
        self.has_delete_permission(request, project.profile.user)
        project.delete()
        return Response({"status": "Success"},status=status.HTTP_204_NO_CONTENT)


# class BasicCreateAPIView(CreateAPIView):
#     permission_classes = (IsAuthenticated,)
#     serializer_class = BasicSerializer
#
#     # will not be used.
#     def post(self, request, *args, **kwargs):
#         post_data = request.data.copy()
#         post_data['profile_id'] = request.user.profile.id
#         print("post_data: {}".format(post_data))
#         serializer = self.serializer_class(data=post_data)
#         if serializer.is_valid():
#             try:
#                 serializer.save()
#             except Exception:
#                 return Response(serializer.errors, status=status.HTTP_409_CONFLICT)
#             return Response(serializer.data, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BasicRetrieveUpdateDestroyAPIView(RetrieveUpdateDestroyAPIView, ModelObjectPermission):
    permission_classes = (IsAuthenticated,)
    serializer_class = BasicSerializer
    model_class = Basic
    def get_queryset(self):
        q_param = self.request.query_params
        search_filter = query_filter(q_param)
        email = q_param.get('email')
        if email:
            queryset = self.model_class.objects.filter(profile__user__email=email).order_by('id')
        elif search_filter:
            queryset = self.model_class.objects.filter(**search_filter).order_by('id')
        else:
            queryset = self.model_class.objects.filter(profile=self.request.user.profile).order_by('id')
        return queryset

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            basics = self.get_queryset()
            projects = self.serializer_class(basics, many=True)
            return Response(projects.data, status=status.HTTP_200_OK)
        raise PermissionDenied

    def put(self, request, *args, **kwargs):
        basic = self.get_queryset()
        if len(basic) >1:
            raise UpdateFailException
        basic = basic.first()
        # Permission check
        self.has_change_permission(request, basic.profile.user)
        data = request.data
        serializer = self.serializer_class(basic, data=data, partial=True)
        if serializer.is_valid(raise_exception=True):
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"Error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    # def delete(self, request, *args, **kwargs):
    #     basic = self.get_queryset()
    #     if len(basic) >1:
    #         raise UpdateFailException
    #     basic = basic.first()
    #     # Permission check
    #     self.has_change_permission(request, basic.profile.user)
    #     basic.delete()
    #     return Response({"status": "Success"},status=status.HTTP_204_NO_CONTENT)


class ExperienceCreateAPIView(CreateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ExperienceSerializer

    # will not be used.
    def post(self, request, *args, **kwargs):
        post_data = request.data.copy()
        post_data['profile_id'] = request.user.profile.id
        serializer = self.serializer_class(data=post_data)
        if serializer.is_valid():
            try:
                serializer.save()
            except Exception:
                return Response(serializer.errors, status=status.HTTP_409_CONFLICT)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ExperienceRetrieveUpdateDestroyAPIView(RetrieveUpdateDestroyAPIView, ModelObjectPermission):
    permission_classes = (IsAuthenticated,)
    serializer_class = ExperienceSerializer
    model_class = Experience

    def get_queryset(self):
        q_param = self.request.query_params
        search_filter = query_filter(q_param)
        email = q_param.get('email')
        if email:
            queryset = self.model_class.objects.filter(profile__user__email=email).order_by('id')
        elif search_filter:
            queryset = self.model_class.objects.filter(**search_filter).order_by('id')
        else:
            queryset = self.model_class.objects.filter(profile=self.request.user.profile).order_by('id')
        return queryset

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            experience = self.get_queryset()
            experiences = self.serializer_class(experience, many=True)
            return Response(experiences.data, status=status.HTTP_200_OK)
        raise PermissionDenied

    def put(self, request, *args, **kwargs):
        experience = self.get_queryset()
        if len(experience) >1:
            raise UpdateFailException
        experience = experience.first()
        # Permission check
        self.has_change_permission(request, experience.profile.user)
        data = request.data
        serializer = self.serializer_class(experience, data=data, partial=True)
        if serializer.is_valid(raise_exception=True):
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"Error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, *args, **kwargs):
        experience = self.get_queryset()
        if len(experience) >1:
            raise UpdateFailException
        experience = experience.first()
        # Permission check
        self.has_delete_permission(request, experience.profile.user)
        experience.delete()
        return Response({"status": "Success"},status=status.HTTP_204_NO_CONTENT)



class EducationCreateAPIView(CreateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = EducationSerializer

    # will not be used.
    def post(self, request, *args, **kwargs):
        post_data = request.data.copy()
        post_data['profile_id'] = request.user.profile.id
        serializer = self.serializer_class(data=post_data)
        if serializer.is_valid():
            try:
                serializer.save()
            except Exception:
                return Response(serializer.errors, status=status.HTTP_409_CONFLICT)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EducationRetrieveUpdateDestroyAPIView(RetrieveUpdateDestroyAPIView, ModelObjectPermission):
    permission_classes = (IsAuthenticated,)
    serializer_class = EducationSerializer
    model_class = Education

    def get_queryset(self):
        q_param = self.request.query_params
        search_filter = query_filter(q_param)
        email = q_param.get('email')
        if email:
            queryset = self.model_class.objects.filter(profile__user__email=email).order_by('id')
        elif search_filter:
            queryset = self.model_class.objects.filter(**search_filter).order_by('id')
        else:
            queryset = self.model_class.objects.filter(profile=self.request.user.profile).order_by('id')
        return queryset

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            education = self.get_queryset()
            educations = self.serializer_class(education, many=True)
            return Response(educations.data, status=status.HTTP_200_OK)
        raise PermissionDenied

    def put(self, request, *args, **kwargs):
        education = self.get_queryset()
        if len(education) >1:
            raise UpdateFailException
        education = education.first()
        # Permission check
        self.has_change_permission(request, education.profile.user)
        data = request.data
        serializer = self.serializer_class(education, data=data, partial=True)
        if serializer.is_valid(raise_exception=True):
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"Error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, *args, **kwargs):
        education = self.get_queryset()
        if len(education) >1:
            raise UpdateFailException
        education = education.first()
        # Permission check
        self.has_delete_permission(request, education.profile.user)
        education.delete()
        return Response({"status": "Success"},status=status.HTTP_204_NO_CONTENT)


class SkillCreateAPIView(CreateAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = SkillSerializer

    # will not be used.
    def post(self, request, *args, **kwargs):
        post_data = request.data.copy()
        post_data['profile_id'] = request.user.profile.id
        serializer = self.serializer_class(data=post_data)
        if serializer.is_valid():
            try:
                serializer.save()
            except Exception:
                return Response(serializer.errors, status=status.HTTP_409_CONFLICT)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SkillRetrieveUpdateDestroyAPIView(RetrieveUpdateDestroyAPIView, ModelObjectPermission):
    permission_classes = (IsAuthenticated,)
    serializer_class = SkillSerializer
    model_class = Skill

    def get_queryset(self):
        q_param = self.request.query_params
        search_filter = query_filter(q_param)
        email = q_param.get('email')
        if email:
            queryset = self.model_class.objects.filter(profile__user__email=email).order_by('id')
        elif search_filter:
            queryset = self.model_class.objects.filter(**search_filter).order_by('id')
        else:
            queryset = self.model_class.objects.filter(profile=self.request.user.profile).order_by('id')
        return queryset

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            skill = self.get_queryset()
            skills = self.serializer_class(skill, many=True)
            return Response(skills.data, status=status.HTTP_200_OK)
        raise PermissionDenied

    def put(self, request, *args, **kwargs):
        skill = self.get_queryset()
        if len(skill) >1:
            raise UpdateFailException
        skill = skill.first()
        # Permission check
        self.has_change_permission(request, skill.profile.user)
        data = request.data
        serializer = self.serializer_class(skill, data=data, partial=True)
        if serializer.is_valid(raise_exception=True):
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"Error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, *args, **kwargs):
        skill = self.get_queryset()
        if len(skill) >1:
            raise UpdateFailException
        skill = skill.first()
        # Permission check
        self.has_change_permission(request, skill.profile.user)
        skill.delete()
        return Response({"status": "Success"},status=status.HTTP_204_NO_CONTENT)

# Test API View
class TestCreateAPIView(CreateAPIView, AdminTypePermission):
    permission_classes = (IsAuthenticated,)
    serializer_class = TestSerializer

    # Only Admin can create Test
    def post(self, request, *args, **kwargs):
        self.has_add_permission(request)

        post_data = request.data.copy()
        serializer = self.serializer_class(data=post_data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TestRetriveUpdateDestroyAPIView(RetrieveUpdateDestroyAPIView, AdminTypePermission):
    permission_classes = (IsAuthenticated, )
    serializer_class = TestSerializer
    model_class = Test

    def get_queryset(self):
        q_param = self.request.query_params
        search_filter = query_filter(q_param)
        if search_filter:
            queryset = self.model_class.objects.filter(**search_filter).order_by('id')
        else:
            queryset= self.model_class.objects.all().order_by('id')
        return queryset

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            test = self.get_queryset()
            tests = self.serializer_class(test, many=True)
            return Response(tests.data, status=status.HTTP_200_OK)
        raise PermissionDenied

    # Only Admin can do change
    def put(self, request, *args, **kwargs):
        test = self.get_queryset()
        if len(test) >1:
            raise UpdateFailException
        test = test.first()
        # Permission check
        self.has_change_permission(request, None)
        data = request.data
        serializer = self.serializer_class(test, data=data, partial=True)
        if serializer.is_valid(raise_exception=True):
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"Error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, *args, **kwargs):
        test = self.get_queryset()
        if len(test) >1:
            raise UpdateFailException
        test = test.first()
        # Permission check
        self.has_delete_permission(request, None)
        test.delete()
        return Response({"status": "Success"},status=status.HTTP_204_NO_CONTENT)

# MyTest Api View

class MyTestCreateAPIView(CreateAPIView, ModelObjectPermission):
    permission_classes = (IsAuthenticated,)
    serializer_class = MyTestSerializer

    # Only Admin can create Test
    def post(self, request, *args, **kwargs):
        self.has_add_permission(request)

        post_data = request.data.copy()
        post_data['profile_id'] = request.user.profile.id

        serializer = self.serializer_class(data=post_data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class MyTestRetriveUpdateDestroyAPIView(RetrieveUpdateDestroyAPIView, ModelObjectPermission):
    permission_classes = (IsAuthenticated, )
    serializer_class = MyTestSerializer
    model_class = MyTest

    def get_queryset(self):
        #TODO: maybe other profile should not see my test
        q_param = self.request.query_params
        search_filter = query_filter(q_param)
        if search_filter:
            queryset = self.model_class.objects.filter(**search_filter).order_by('id')
        else:
            queryset= self.model_class.objects.filter(profile = self.request.user.profile).order_by('id')
        return queryset

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            test = self.get_queryset()
            tests = self.serializer_class(test, many=True)
            return Response(tests.data, status=status.HTTP_200_OK)
        raise PermissionDenied

    # Only Admin can do change
    def put(self, request, *args, **kwargs):
        test = self.get_queryset()
        if len(test) >1:
            raise UpdateFailException
        test = test.first()
        # Permission check
        self.has_change_permission(request, test.profile.user)
        data = request.data
        serializer = self.serializer_class(test, data=data, partial=True)
        if serializer.is_valid(raise_exception=True):
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"Error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, *args, **kwargs):
        test = self.get_queryset()
        if len(test) >1:
            raise UpdateFailException
        test = test.first()
        # Permission check
        self.has_delete_permission(request, test.profile.user)
        test.delete()
        return Response({"status": "Success"},status=status.HTTP_204_NO_CONTENT)



#
#   Question API View
#
class QuestionCreateAPIView(CreateAPIView, AdminTypePermission):
    permission_classes = (IsAuthenticated,)
    serializer_class = QuestionSerializer

    # Only Admin can create Test
    def post(self, request, *args, **kwargs):
        self.has_add_permission(request)

        post_data = request.data.copy()

        serializer = self.serializer_class(data=post_data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class QuestionRetriveUpdateDestroyAPIView(RetrieveUpdateDestroyAPIView, AdminTypePermission):
    permission_classes = (IsAuthenticated, )
    serializer_class = QuestionSerializer
    model_class = Question

    def get_queryset(self):
        q_param = self.request.query_params
        search_filter = query_filter(q_param)
        queryset = self.model_class.objects.filter(**search_filter).order_by('id')
        return queryset

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            question = self.get_queryset()
            question = self.serializer_class(question, many=True)
            return Response(question.data, status=status.HTTP_200_OK)
        raise PermissionDenied

    # Only Admin can do change
    def put(self, request, *args, **kwargs):
        question = self.get_queryset()
        if len(question) >1:
            raise UpdateFailException
        question = question.first()
        # Permission check
        self.has_change_permission(request, None)
        data = request.data
        serializer = self.serializer_class(question, data=data, partial=True)
        if serializer.is_valid(raise_exception=True):
            self.perform_update(serializer)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({"Error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, *args, **kwargs):
        question = self.get_queryset()
        if len(question) >1:
            raise UpdateFailException
        test = question.first()
        # Permission check
        self.has_delete_permission(request, None)
        test.delete()
        return Response({"status": "Success"},status=status.HTTP_204_NO_CONTENT)
