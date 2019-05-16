from django import http
from django.shortcuts import render

# Create your views here.
from django.views import View
from django_redis import get_redis_connection

from meiduo_mall.apps.verifications.libs.captcha.captcha import captcha


class ImageCodeView(View):
    """图形验证码"""

    def get(self, request, uuid):
        """
        :param request: 请求对象
        :param uuid: 当前用户的唯一id
        :return: image/jpg
        """
        # 生成图片验证码
        text, image = captcha.generate_captcha()

        # 保存图片验证码
        redis_conn = get_redis_connection('verify_code')

        # 图形验证码有效期，单位：秒
        # IMAGE_CODE_REDIS_EXPIRES = 300
        redis_conn.setex('img_%s' % uuid, 300, text)

        # 响应图片验证码
        return http.HttpResponse(image, content_type='imgae/jpg')