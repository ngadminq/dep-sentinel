from flask import Flask, request
import yaml

app = Flask(__name__)


@app.post("/import")
def import_config():
    # 用户上传 YAML 配置文件
    cfg = yaml.load(request.files["file"].read(), Loader=yaml.FullLoader)
    return {"keys": list(cfg)}
