from django.db import models
from django.contrib import admin
import random, string


def gen_random():
    return str("".join(random.choices(string.ascii_lowercase + string.digits, k=10)))


class OAuthUser(models.Model):
    code_verifier = models.TextField(max_length=500)
    code_challenge = models.CharField(max_length=300)
    id = models.CharField(
        primary_key=True, max_length=100, unique=True, default=gen_random
    )
    refresh_token = models.CharField(max_length=100, blank=True)
    jwt_token = models.TextField(blank=True)

    class Meta:
        verbose_name = "OAuthUser"

    def __str__(self) -> str:
        return self.id
