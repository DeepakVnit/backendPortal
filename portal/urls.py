"""portal URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework_jwt.views import obtain_jwt_token
from rest_framework_jwt.views import verify_jwt_token
from rest_framework_jwt.views import refresh_jwt_token
from portalapp import views as appview
from django.conf import settings
from django.conf.urls.static import static

app_name = 'portalapp'

urlpatterns = [

    path('register/', appview.RegistrationAPIView.as_view(), name='register'),
    path('user/', appview.UserRetrieveUpdateAPIView.as_view(), name='user'),
    path('login/', appview.LoginAPIView.as_view(), name='login'),
    path('change_password/', appview.UpdatePassword.as_view()),


    path('accounts/profile/', appview.ProfileRetrieveAPIView.as_view()),
    path('accounts/project/', appview.ProjectRetrieveUpdateDestroyAPIView.as_view()),
    path('accounts/project/create', appview.ProjectCreateAPIView.as_view()),

    path('accounts/basic/', appview.BasicRetrieveUpdateDestroyAPIView.as_view()),
    # path('accounts/basic/create', appview.BasicCreateAPIView.as_view()),

    path('accounts/education/', appview.EducationRetrieveUpdateDestroyAPIView.as_view()),
    path('accounts/education/create', appview.EducationCreateAPIView.as_view()),

    path('accounts/experience/', appview.ExperienceRetrieveUpdateDestroyAPIView.as_view()),
    path('accounts/experience/create', appview.ExperienceCreateAPIView.as_view()),

    path('accounts/skill/', appview.SkillRetrieveUpdateDestroyAPIView.as_view()),
    path('accounts/skill/create', appview.SkillCreateAPIView.as_view()),

    path('accounts/test/', appview.TestRetriveUpdateDestroyAPIView.as_view()),
    path('accounts/test/create', appview.TestCreateAPIView.as_view()),

    path('accounts/mytest/', appview.MyTestRetriveUpdateDestroyAPIView.as_view()),
    path('accounts/mytest/create', appview.MyTestCreateAPIView.as_view()),
    path('accounts/question/', appview.QuestionRetriveUpdateDestroyAPIView.as_view()),
    path('accounts/question/create', appview.QuestionCreateAPIView.as_view()),

    # path('authenticate/', appview.set_request_user),
    # path('social_jwt_token/', include('rest_social_auth.urls_jwt', namespace="social_jwt_token")),
    # path('social/', include('social_django.urls', namespace='social')),
    # path('auth/', include('rest_framework_social_oauth2.urls', namespace='auth')),


    path('admin/', admin.site.urls),
    path('api-token-auth/', obtain_jwt_token),
    path('api-token-refresh/', refresh_jwt_token),
    path('api-token-verify/', verify_jwt_token),

] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

if settings.DEBUG is True:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

