from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="index"),
    path("verify/", views.verify, name="verify"),
    path("invoke/", views.invoke, name="invoke"),
]
