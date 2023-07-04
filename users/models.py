from django.contrib.auth.models import AbstractUser
from django.db import models
from rest_framework import serializers
# Create your models here.
class User(AbstractUser):
    name  = models.CharField(max_length=255)
    email = models.CharField(max_length=255,unique=True)
    password = models.CharField(max_length=255)
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
