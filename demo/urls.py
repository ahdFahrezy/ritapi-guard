from django.urls import path
from .views import demo_page

urlpatterns = [
    path("page/", demo_page, name="demo-page"),
]
