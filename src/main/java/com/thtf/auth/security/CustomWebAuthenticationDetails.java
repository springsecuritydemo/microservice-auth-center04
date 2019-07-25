package com.thtf.auth.security;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * ========================
 * 获取用户登录时携带的额外信息
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/24 16:50
 * Version: v1.0
 * ========================
 */
public class CustomWebAuthenticationDetails extends WebAuthenticationDetails {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final String uuid;          //验证码key
    private final String verifyCode;    //验证码value


    public CustomWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.uuid = request.getParameter("uuid");
        this.verifyCode = request.getParameter("verifyCode");
    }

    public String getUuid() {
        return uuid;
    }

    public String getVerifyCode() {
        return verifyCode;
    }
}
