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
    # 订单确认
    url(r'^orders/settlement/$', views.OrderSettlementView.as_view(), name='settlement'),
    # 订单提交
    url(r'^orders/commit/$', views.OrderCommitView.as_view()),
    # 订单提交成功过渡页面
    url(r'^orders/success/$', views.OrderSuccessView.as_view()),
    # 我的订单
    url(r'^orders/info/(?P<page_num>\d+)/$', views.UserOrderInfoView.as_view(), name='info'),
    # 订单商品评价
    url(r'^orders/comment/(?P<order_id>\d+)/$', views.OrderCommentView.as_view()),
    url(r'^orders/comment/$', views.OrderCommentView.as_view()),
]
