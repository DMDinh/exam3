from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^register$', views.register),
    url(r'^login$', views.login),
    url(r'^friends$', views.friends),
    url(r'^logout$', views.logout),
    url(r'^user/(?P<id>\d+)$', views.user),
    url(r'^addfriend/(?P<id>\d+)$', views.addfriend),
    url(r'^remove/(?P<id>\d+)$', views.remove),


]
