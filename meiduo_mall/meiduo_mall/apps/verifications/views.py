import random
import logging
logger = logging.getLogger('django')

from django import http
from django.views import View
from django_redis import get_redis_connection
from meiduo_mall.libs.captcha.captcha import captcha
from celery_tasks.sms.tasks import ccp_send_sms_code
from meiduo_mall.utils import constants
from meiduo_mall.utils.response_code import RETCODE


class ImageCodeView(View):
    """图形验证码"""

    """
    参数名	类型	是否必传	说明
    uuid	string	是	唯一编号
    """
    def get(self, request, uuid):
        """
        :param request: 请求对象
        :param uuid: 唯一标识图形验证码所属于的用户
        :return: image/jpg
        """

        #生成图片验证码
        text,image = captcha.generate_captcha()

        #获取redis连接对象
        redis_conn = get_redis_connection('verify_code')

        #保存图片验证码
        #redis_conn.setex(键，过期时间，值)
        redis_conn.setex('img_%s' % uuid, constants.IMAGE_CODE_REDIS_EXPIRES, text)

        #响应图片验证码
        return http.HttpResponse(image,content_type='image/jpg')



class SMSCodeView(View):
    """短信验证码"""

    """
    参数名	类型	是否必传	说明
    mobile	string	是	手机号
    image_code	string	是	图形验证码
    image_code_id	string	是	唯一编号
    """

    def get(self, reqeust, mobile):
        """
        :param reqeust: 请求对象
        :param mobile: 手机号
        :return: JSON
        """


        #1 创建连接到redis的对象
        redis_conn = get_redis_connection('verify_code')

        #2 判断60秒内是否重复访问
        send_flag = redis_conn.get('send_flag_%s' % mobile)
        if send_flag:
            return http.JsonResponse({'code': RETCODE.THROTTLINGERR, 'errmsg': '发送短信过于频繁'})

        #3 接收参数
        image_code_client = reqeust.GET.get('image_code')
        uuid = reqeust.GET.get('image_code_id')

        #4 验证参数
        if not all([image_code_client,uuid]):
            return http.JsonResponse({'code': RETCODE.NECESSARYPARAMERR, 'errmsg': '缺少必传参数'})

        #5 提取图形验证码
        image_code_server = redis_conn.get('img_%s' % uuid)
        if image_code_server is None:
            # 图形验证码过期或者不存在
            return http.JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图形验证码失效'})

        #6 删除图形验证码，避免同一个图形验证码多次比较
        try:
            redis_conn.delete('img_%s' % uuid)
        except Exception as e:
            logger.error(e)

        #7 对比图形验证码
        image_code_server = image_code_server.decode()  # bytes转字符串
        if image_code_client.lower() != image_code_server.lower():  # 转小写后比较
            return http.JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '输入图形验证码有误'})

        #8 生成短信验证码：生成6位数验证码
        sms_code = random.randint(0,999999)  #sms_code = 6位随机验证码
        logger.info(sms_code)
        print(sms_code)

        #9 创建Redis管道
        pl = redis_conn.pipeline()
        # 将Redis请求添加到队列
        pl.setex('sms_%s' % mobile, constants.SMS_CODE_REDIS_EXPIRES, sms_code)
        pl.setex('send_flag_%s' % mobile, constants.SEND_SMS_CODE_INTERVAL, 1)
        # 执行请求
        pl.execute()

        # Celery 异步发送短信验证码
        ccp_send_sms_code.delay(mobile, sms_code)

        #11 响应结果
        return http.JsonResponse({'code': RETCODE.OK, 'errmsg': '发送短信成功'})
