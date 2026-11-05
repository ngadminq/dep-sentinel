from flask import Flask, request
import requests
from jinja2.sandbox import SandboxedEnvironment

app = Flask(__name__)
env = SandboxedEnvironment()


@app.get("/render")
def render():
    # 运营在后台填写通知模板，用沙箱渲染
    return env.from_string(request.args["tpl"]).render(user="test")


@app.get("/weather")
def weather():
    return requests.get("https://api.example.com/weather").json()
