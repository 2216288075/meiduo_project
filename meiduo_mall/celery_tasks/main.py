# 导入 Celery 类
import os

from celery import Celery


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'meiduo_mall.settings.dev')

# 创建 celery 实例
celery_app = Celery('meiduo')


# 给 celery 添加配置
# 里面的参数为我们创建的 config 配置文件:
celery_app.config_from_object('celery_tasks.config')


# 让 celery_app 自动捕获目标地址下的任务
celery_app.autodiscover_tasks(['celery_tasks.sms', 'celery_tasks.email'])