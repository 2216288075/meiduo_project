"""meiduo_mall URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls import url

from . import views

urlpatterns = [
    # 购物车查询和新增和修改和删除
    url(r'^carts/$', views.CartsView.as_view(), name='info'),
    # 购物车全选
    url(r'^carts/selection/$', views.CartsSelectAllView.as_view()),
    # 提供商品页面右上角购物车数据
    url(r'^carts/simple/$', views.CartsSimpleView.as_view()),
]
