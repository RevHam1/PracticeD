from django.urls import path
from . import views

urlpatterns = [
    ## Register & Login
    path('', views.index),
    path('register', views.register),
    path('login', views.login),
    path('groups', views.groups),
    path('logout', views.logout),

    path('group/create', views.create_group),
    path('group/<int:group_id>', views.show_group),

    path('group/add/<int:group_id>', views.add_membership),
    path('group/remove/<int:group_id>', views.remove_membership),

    path('group/delete/<int:group_id>', views.delete_group),
]