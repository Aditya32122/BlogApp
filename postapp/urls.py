from django.urls import path
from .views import RegisterView, LoginView, register_page, login_page, logout_view, home

urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='api_register'),
    path('api/login/', LoginView.as_view(), name='api_login'),
    path('register/', register_page, name='register'),
    path('login/', login_page, name='login'),
    path('logout/', logout_view, name='logout'),
    path('', home, name='home'),
]