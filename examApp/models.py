from django.db import models
import re
import bcrypt

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

## ************************* UserManager & User ****************************** ##
class UserManager(models.Manager):
    def reg_validator(self, postData):
        errors = {}
        if len(postData['first_name']) == 0:
            errors['first_name'] = "First name is required!"
        elif len(postData['first_name']) < 2 or postData['first_name'].isalpha() != True:
            errors['first_name'] = "First name must be at least 2 charactors long, letters only!"
        if len(postData['last_name']) == 0:
            errors['last_name'] = "Last name is required!"
        elif len(postData['last_name']) < 2 or postData['last_name'].isalpha() != True:
            errors['last_name'] = "Last name must be at least 2 charactors long, letters only!"

        if len(postData['email']) == 0:
            errors['email'] = "Email is required!"
        elif not EMAIL_REGEX.match(postData['email']):
            errors['email'] = "Invalid email format!"
        elif User.objects.filter(email = postData['email']).exists():
            errors['email'] = "Email already registed"

        if len(postData['password']) == 0:
            errors['password'] = "Password is required!"
        elif len(postData['password']) < 8:
            errors['password'] = "Password must be at least 8 charactors long!"
        elif postData['password'] != postData['confirm_pw']:
            errors['password'] = "Password and Confirmed Password must match."
        return errors

    def log_validator(self, postData):
        errors = {}
        if len(postData['email']) == 0:
            errors['email'] = "Email is required!"
        elif not EMAIL_REGEX.match(postData['email']):
            errors['email'] = "Invalid email format!"

        if len(postData['password']) == 0:
            errors['password'] = "Password is required!"
        return errors

class User(models.Model):
    first_name = models.CharField(max_length=60)
    last_name = models.CharField(max_length=60)
    email = models.CharField(max_length=60)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = UserManager()

## ************************* GroupManager & Group ****************************** ##
class GroupManager(models.Manager):
    def group_validator(self, postData):
        errors = {}

        if len(postData['name']) == 0:
            errors['name'] = "Name is required!"
        elif len(postData['name']) < 5:
            errors['name'] = "First name must be at least 5 charactors long!"
        if len(postData['description']) < 3:
            errors['description'] = "Description must be more than 10 characters!" 

        return errors

class Group(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    member = models.ForeignKey(User, related_name='groups_joined', on_delete=models.CASCADE)
    users_that_joined = models.ManyToManyField(User, related_name='groups_entered')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = GroupManager()
