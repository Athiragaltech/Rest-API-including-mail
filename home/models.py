# models.py
from django.contrib.auth.models import User
from django.db import models


class HomePhoneNumber(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20)

    def __str__(self):
        return self.phone_number
