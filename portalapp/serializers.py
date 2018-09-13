from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from .models import (Profile, Basic, Experience,
                    Education, Skill, Project,Test,
                     MyTest, User, Question)

class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True,
        required=True
    )
    token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'token']

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255)
    username = serializers.CharField(max_length=255, read_only=True)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)

    def validate(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        if email is None:
            raise serializers.ValidationError(
                'An email address is required to log in.'
            )

        if password is None:
            raise serializers.ValidationError(
                'A password is required to log in.'
            )
        user = authenticate(username=email, password=password)

        if user is None:
            raise serializers.ValidationError(
                'A user with this email and password was not found.'
            )
        if not user.is_active:
            raise serializers.ValidationError(
                'This user has been deactivated.'
            )

        return {
            'email': user.email,
            'username': user.username,
            'token': user.token
        }


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value

class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """
    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    new_password1 = serializers.CharField(required=True)
    new_password2 = serializers.CharField(required=True)

    def validate_new_password1(self, value):
        validate_password(value)
        return value


from django.conf import settings
from django.core.validators import validate_email
from .exceptions import EmailValidationException
from django.contrib.auth import get_user_model

UserModel = get_user_model()

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, value):
        try:
            validate_email(value)
        except Exception:
            raise EmailValidationException
        return
    #(u for u in active_users if u.has_usable_password())
    def save(self):
        email = self.cleaned_data["email"]
        active_users = UserModel._default_manager.filter(**{
            '%s__iexact' % UserModel.get_email_field_name(): email,
            'is_active': True,
        })
        user = active_users.first()

        # context = {
        #     'email': email,
        #     'domain': "www.example.com",
        #     'site_name': "www.example.com",
        #     'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
        #     'user': user,
        #     'token': token_generator.make_token(user),
        #     'protocol': 'https' if use_https else 'http',
        # }
        # if extra_email_context is not None:
        #     context.update(extra_email_context)
        # self.send_mail(
        #     subject_template_name, email_template_name, context, from_email,
        #     email, html_email_template_name=html_email_template_name,
        # )


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)
    uid = serializers.CharField()
    token = serializers.CharField()

    # set_password_form_class = SetPasswordForm
    #
    # def custom_validation(self, attrs):
    #     pass
    #
    # def validate(self, attrs):
    #     self._errors = {}
    #
    #     # Decode the uidb64 to uid to get User object
    #     try:
    #         uid = force_text(uid_decoder(attrs['uid']))
    #         self.user = UserModel._default_manager.get(pk=uid)
    #     except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
    #         raise ValidationError({'uid': ['Invalid value']})
    #
    #     self.custom_validation(attrs)
    #     # Construct SetPasswordForm instance
    #     self.set_password_form = self.set_password_form_class(
    #         user=self.user, data=attrs
    #     )
    #     if not self.set_password_form.is_valid():
    #         raise serializers.ValidationError(self.set_password_form.errors)
    #     if not default_token_generator.check_token(self.user, attrs['token']):
    #         raise ValidationError({'token': ['Invalid value']})

        # return attrs

    def save(self):
        return self.set_password_form.save()


# Application Specific
class ProjectSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='profile.user.username', read_only=True)
    profile_id = serializers.IntegerField(write_only=True)
    id = serializers.IntegerField(read_only=True)
    class Meta:
        model = Project
        fields = ('id','username', 'headline', 'description', 'from_date', 'to_date', 'ptype', 'extra_info', 'profile_id')



class BasicSerializer(serializers.ModelSerializer):
    profile_id = serializers.IntegerField(write_only=True)
    id = serializers.IntegerField(read_only=True)
    class Meta:
        model = Basic
        fields = ('id','dob', 'phone', 'city', 'state', 'country', 'interest', 'website', 'profile_id')


class ExperienceSerializer(serializers.ModelSerializer):
    profile_id = serializers.IntegerField(write_only=True)
    id = serializers.IntegerField(read_only=True)
    class Meta:
        model = Experience
        fields = ('id', 'designation', 'company', 'start_date', 'end_date', 'profile_id', )


class EducationSerializer(serializers.ModelSerializer):
    profile_id = serializers.IntegerField(write_only=True)
    id = serializers.IntegerField(read_only=True)
    class Meta:
        model = Education
        fields = ('id','education_level', 'branch', 'institute', 'start_date', 'end_date', 'profile_id',)


class SkillSerializer(serializers.ModelSerializer):
    profile_id = serializers.IntegerField(write_only=True)
    id = serializers.IntegerField(read_only=True)
    class Meta:
        model = Skill
        fields = ('id','skill', 'last_used', 'profile_id',)


class ProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username')
    bio = serializers.CharField(allow_blank=True, required=False)
    image = serializers.SerializerMethodField()
    basic = BasicSerializer(read_only=True)
    experience = ExperienceSerializer(source='experience_set', many=True, default=[])
    education = EducationSerializer(source='education_set', many=True, default=[])
    skills = SkillSerializer(source='skill_set', many=True, default=[])
    projects = ProjectSerializer(source='project_set', many=True, default=[])
    id = serializers.IntegerField(read_only=True)
    class Meta:
        model = Profile
        fields = ('id','username', 'bio', 'image','basic', 'experience', 'education', 'skills', 'projects')
        read_only_fields = ('username',)

    def get_image(self, obj):
        if obj.image:
            return obj.image.url
        return 'https://static.productionready.io/images/smiley-cyrus.jpg' #TODO


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=128,
        min_length=8,
        write_only=True
    )
    bio = serializers.CharField(source='profile.bio')
    image = serializers.SerializerMethodField(source='mystatic/None/1.jpg')
    id = serializers.IntegerField(read_only=True)
    class Meta:
        model = User
        fields = ('id','email', 'username','password', 'bio', 'image')

    def get_image(self, obj):
        if obj.profile.image:
            return obj.profile.image.url
        return 'https://static.productionready.io/images/smiley-cyrus.jpg' #TODO

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        profile_data = validated_data.pop('profile', {})

        for (key, value) in validated_data.items():
            setattr(instance, key, value)

        if password is not None:
            instance.set_password(password)

        instance.save()

        for (key, value) in profile_data.items():
            setattr(instance.profile, key, value)

        instance.profile.save()

        return instance

class TestSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    class Meta:
        model = Test
        fields = ('id','topic', 'level', 'sub_topic', 'ask_question',)


class MyTestSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    profile_id = serializers.CharField()
    test_id = serializers.CharField()
    class Meta:
        model = MyTest
        fields = ('id','profile_id', 'test_id', 'attempted', 'total_ques', 'correct', 'wrong', 'percentage', 'status')

class QuestionSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    class Meta:
        model = Question
        fields = ('id','question', 'answer', 'option', 'topic', 'sub_topic', 'level',)
