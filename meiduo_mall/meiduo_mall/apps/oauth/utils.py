# 导入:
from django.conf import settings
from itsdangerous import TimedJSONWebSignatureSerializer
from itsdangerous import BadData


# 定义函数, 检验传入的 access_token 里面是否包含有 openid
from meiduo_mall.utils import constants


def check_access_token(access_token):
    """
    检验用户传入的 token
    :param token: token
    :return: openid or None
    """

    # 调用 itsdangerous 中的类, 生成对象
    serializer = TimedJSONWebSignatureSerializer(settings.SECRET_KEY,
                                                 expires_in=constants.SAVE_QQ_USER_TOKEN_EXPIRES)

    try:
        # 尝试使用对象的 loads 函数
        # 对 access_token 进行反序列化( 类似于解密 )
        # 查看是否能够获取到数据:
        data = serializer.loads(access_token)

    except BadData:
        # 如果出错, 则说明 access_token 里面不是我们认可的.
        # 返回 None
        return None
    else:
        # 如果能够从中获取 data, 则把 data 中的 openid 返回
        return data.get('openid')