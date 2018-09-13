from django.contrib import admin, auth
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

    path('password/forgot/', appview.ForgotPassword.as_view(), name='forgot_password'),
    path('password/reset/<uidb64>-<token>/', appview.password_reset_confirm, name='password_reset_confirm'),
    path('password/new_password/', appview.NewPasswordUpdate.as_view(), name='apply_new_password'),

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

