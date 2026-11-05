package com.demo;

import javax.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LoginController {
    private static final Logger logger = LogManager.getLogger(LoginController.class);

    public String login(HttpServletRequest request) {
        // 记录登录来源，排查撞库
        logger.info("login attempt, ua={}", request.getHeader("User-Agent"));
        return "ok";
    }
}
