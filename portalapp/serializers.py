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
