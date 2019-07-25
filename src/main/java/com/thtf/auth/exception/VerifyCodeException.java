package com.thtf.auth.exception;


import org.springframework.security.core.AuthenticationException;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/24 15:02
 * Version: v1.0
 * ========================
 */
public class VerifyCodeException extends AuthenticationException {

    public VerifyCodeException(String msg) {
        super(msg);
    }

    public VerifyCodeException(String msg, Throwable t) {
        super(msg, t);
    }
}
