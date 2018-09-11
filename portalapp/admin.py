from django.contrib import admin

# Register your models here.
from .models import User, Profile, Basic, Experience, Education, Skill, Project, Test, MyTest, Question

@admin.register(User)
class AllUsers(admin.ModelAdmin):
    list_display = [
        'username',
        'email',
        'is_superuser',
        'is_active',
        'is_staff',
    ]
    ordering = ('email',)

@admin.register(Test)
class AllTests(admin.ModelAdmin):
    list_display = [
        'topic',
        'level',
        'sub_topic',
        'ask_question',
    ]

@admin.register(MyTest)
class MyTests(admin.ModelAdmin):
    list_display = [
        'profile',
        'test',
        'attempted',
        'total_ques',
        'correct',
        'wrong',
        'status',
        'percentage',
    ]

@admin.register(Question)
class Questions(admin.ModelAdmin):
    list_display = [
        'question',
        'option',
        'answer',
        'topic',
        'sub_topic',
        'level',
    ]


@admin.register(Profile)
class UserProfiles(admin.ModelAdmin):
    list_display = [
        'id',
        'Email',
        'User',
        'bio',
        'image',
    ]
    def Email(self, obj):
        return obj.user.email

    def User(self, obj):
        return obj.user.username

    ordering = ('user',)
    list_filter = (
        ('user', admin.RelatedFieldListFilter),
    )

@admin.register(Basic)
class UserProfiles(admin.ModelAdmin):
    list_display = [
        'profile',
        'dob',
        'phone',
        'city',
        'state',
        'interest',
        'website'
    ]

    def profile(self, obj):
        return obj.profile.user.username

    ordering = ('profile',)
    list_filter = (
        ('profile', admin.RelatedFieldListFilter),
    )

@admin.register(Experience)
class UserProfiles(admin.ModelAdmin):
    list_display = [
        'username',
        'designation',
        'company',
        'start_date',
        'end_date',
    ]

    def username(self, obj):
        return obj.profile.user.username

    ordering = ('profile',)


@admin.register(Education)
class UserProfiles(admin.ModelAdmin):
    list_display = [
        'username',
        'education_level',
        'branch',
        'institute',
        'start_date',
        'end_date'
    ]

    def username(self, obj):
        return obj.profile.user.username

    ordering = ('profile',)


@admin.register(Skill)
class UserProfiles(admin.ModelAdmin):
    list_display = [
        'username',
        'skill',
        'last_used',
    ]

    def username(self, obj):
        return obj.profile.user.username

    ordering = ('profile',)


@admin.register(Project)
class UserProfiles(admin.ModelAdmin):
    list_display = [
        'username',
        'headline',
        'description',
        'from_date',
        'to_date',
        'ptype',
        'extra_info',
    ]

    def username(self, obj):
        return obj.profile.user.username

    ordering = ('profile',)
