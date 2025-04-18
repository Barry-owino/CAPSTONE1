from django.urls import path
from .views import UserRegisterView, UserLoginView, UserUpdateView

urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='user-register'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('user/update/<int:pk>/', UserUpdateView.as_view(), name='user-update'),

]
