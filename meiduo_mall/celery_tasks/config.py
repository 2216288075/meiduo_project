# 指定消息队列的位置, 使用方式:
broker_url= 'redis://106.52.66.63:6379/13'

# 例如:
# meihao: 在rabbitq中创建的用户名, 注意: 远端链接时不能使用guest账户.
# 123456: 在rabbitq中用户名对应的密码
# ip部分: 指的是当前rabbitq所在的电脑ip
# 5672: 是规定的端口号
# broker_url = 'amqp://meihao:123456@172.16.238.128:5672'