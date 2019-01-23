from django.conf.urls import url
from salt import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^login/', views.acc_login, name='login'),
    url(r'^logout/', views.acc_logout, name='logout'),
    url(r'^saltstack/', views.saltstack, name='saltstack'),
    url(r'^download/', views.download, name="download"),
    url(r'^switch/', views.nginx_switch, name="switch"),
]
