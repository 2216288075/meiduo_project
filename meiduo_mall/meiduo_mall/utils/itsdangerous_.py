from django.conf import settings
from itsdangerous import TimedJSONWebSignatureSerializer

from meiduo_mall.utils import constants


def generate_access_token(openid):
    """
    签名 openid
    :param openid: 用户的 openid
    :return: access_token
    """

    # QQ登录保存用户数据的token有效期
    # settings.SECRET_KEY: 加密使用的秘钥
    # SAVE_QQ_USER_TOKEN_EXPIRES = 600: 过期时间
    serializer = TimedJSONWebSignatureSerializer(settings.SECRET_KEY,
                                                 expires_in=constants.ACCESS_TOKEN_EXPIRES)
    data = {'openid': openid}
    token = serializer.dumps(data)
    return token.decode()