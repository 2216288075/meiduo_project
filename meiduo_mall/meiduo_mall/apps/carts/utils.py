import base64
import pickle

from django_redis import get_redis_connection


def merge_cart_cookie_to_redis(request, user, response):
    """
    登录后合并cookie购物车数据到Redis
    :param request: 本次请求对象，获取 cookie 中的数据
    :param response: 本次响应对象，清除 cookie 中的数据
    :param user: 登录用户信息，获取 user_id
    :return: response
    """
    # 获取cookie中的购物车数据
    cookie_cart = request.COOKIES.get('carts')
    # cookie中没有数据就响应结果
    if not cookie_cart:
        return response
    cart_dict = pickle.loads(base64.b64decode(cookie_cart.encode()))

    new_dict = {}
    new_add = []
    new_remove = []
    #同步cookie 中购物车数据
    for sku_id,item in cart_dict.items():
        new_dict[sku_id] = item['count']

        if item['selected']:
            new_add.append(sku_id)
        else:
            new_remove.append(sku_id)

    # 将new_cart_dict写入到Redis数据库
    redis_coon = get_redis_connection('carts')
    pl = redis_coon.pipeline()
    pl.hmset('carts_%s' % user.id, new_dict)
    # 将勾选状态同步到Redis数据库
    if new_add:
        pl.sadd('selected_%s' % user.id, *new_add)
    if new_remove:
        pl.srem('selected_%s' % user.id, *new_remove)
    pl.execute()

    # 清除cookie
    response.delete_cookie('carts')

    return response