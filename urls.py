from django.urls import path
from .views import signup, login  
from django.contrib.auth import views as auth_views

urlpatterns = [
    # Custom Authentication Endpoints        
    path('register/', signup, name='register'),  # Add this!
    path('login/', login, name='login'),     

    # Django Built-in Authentication Endpoints
    path('api/auth/login/', auth_views.LoginView.as_view(template_name="login.html"), name='auth_login'),
    path('api/auth/logout/', auth_views.LogoutView.as_view(next_page='auth_login'), name='auth_logout'),
]
