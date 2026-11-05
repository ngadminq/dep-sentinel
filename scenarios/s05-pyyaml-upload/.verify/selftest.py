"""项目自带的冒烟测试：升级后要保证正常的配置文件还能照常解析。"""
import yaml

cfg = yaml.load("name: order-service\nreplicas: 3\n", Loader=yaml.FullLoader)
assert cfg == {"name": "order-service", "replicas": 3}, cfg
print("ok")
