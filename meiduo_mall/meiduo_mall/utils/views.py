#导入：
from django import http
from django.contrib.auth.decorators import login_required

# 添加扩展类:
# 因为这类扩展其实就是 Mixin 扩展类的扩展方式
# 所以我们起名时, 最好也加上 Mixin 字样, 不加也可以.
from meiduo_mall.utils.response_code import RETCODE


class LoginRequiredMixin(object):
  """验证用户是否登录的扩展类"""

  @classmethod
  def as_view(cls,**initkwargs):
      # 调用父类的 as_view() 函数
      view = super().as_view()
      return login_required(view)




# 导入:
from django.utils.decorators import wraps

def login_required_json(view_func):
    """
    判断用户是否登录的装饰器，并返回 json
    :param view_func: 被装饰的视图函数
    :return: json、view_func
    """
    # 恢复 view_func 的名字和文档
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):

        # 如果用户未登录，返回 json 数据
        if not request.user.is_authenticated():
            return http.JsonResponse({'code': RETCODE.SESSIONERR, 'errmsg': '用户未登录'})
        else:
            # 如果用户登录，进入到 view_func 中
            return view_func(request, *args, **kwargs)

    return wrapper


class LoginRequiredJSONMixin(object):
    """验证用户是否登陆并返回 json 的扩展类"""
    @classmethod
    def as_view(cls, **initkwargs):
        view = super().as_view(**initkwargs)
        return login_required_json(view)
