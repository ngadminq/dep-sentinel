package com.demo;

import com.alibaba.fastjson.JSON;
import javax.servlet.http.HttpServletRequest;

public class OrderApi {
    // 老项目：没有 pom.xml，依赖是十年前直接拷进 WEB-INF/lib 的
    public Object create(HttpServletRequest request) throws Exception {
        String body = new String(request.getInputStream().readAllBytes(), "UTF-8");
        return JSON.parseObject(body);
    }
}
