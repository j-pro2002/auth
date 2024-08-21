from django.db import models

# Create your models here.
#create User model
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    name = models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    username = None

    USERNAME_FIELD = 'email' # login w/ email, unique identifier.
    REQUIRED_FIELDS = [] 

