package com.thtf.auth.controller;

import cn.hutool.core.codec.Base64;
import com.thtf.auth.exception.VerifyCodeException;
import com.thtf.auth.response.ImgResult;
import com.thtf.auth.response.Result;
import com.thtf.auth.util.VerifyCodeUtils;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/23 10:40
 * Version: v1.0
 * ========================
 */
@Slf4j
@Controller
public class LoginController {
    private Logger logger = LoggerFactory.getLogger(LoginController.class);

    // 登录验证码过期时间：单位 分钟
    @Value("${loginCode.expiration}")
    private Long expiration;

    @Value("${loginCode.prefix}")
    private String prefix;


    @Autowired
    private StringRedisTemplate redisTemplate;

    /**
     * 获取验证码
     */
    @GetMapping("/vCode")
    @ResponseBody
    public ImgResult getCode() throws IOException {

        // 生成随机字串
        String verifyCode = VerifyCodeUtils.generateVerifyCode(4);
        String uuid = UUID.randomUUID().toString();
        // 存入redis
        redisTemplate.opsForValue().set(prefix + uuid, verifyCode, expiration, TimeUnit.MINUTES);
        // 生成图片
        int w = 111, h = 36;
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        VerifyCodeUtils.outputImage(w, h, stream, verifyCode);
        try {
            return new ImgResult(Base64.encode(stream.toByteArray()),uuid);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            stream.close();
        }
    }

    @GetMapping("/login")
    public String showLogin() {
        return "login.html";
    }

    @GetMapping("/")
    public String showHome() {
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("当前登陆用户：" + name);

        return "index.html";
    }

    @RequestMapping("/login/error")
    @ResponseBody
    public Result loginError(HttpServletRequest request) {
        AuthenticationException authenticationException = (AuthenticationException) request.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        log.info("authenticationException={}", authenticationException);
        Result result = new Result();
        result.setCode(201);

        // 图片验证码校验
        if(authenticationException instanceof VerifyCodeException) {
            result.setMsg(authenticationException.getMessage());
        } else if (authenticationException instanceof UsernameNotFoundException || authenticationException instanceof BadCredentialsException) {
            result.setMsg("用户名或密码错误");
        } else if (authenticationException instanceof DisabledException) {
            result.setMsg("用户已被禁用");
        } else if (authenticationException instanceof LockedException) {
            result.setMsg("账户被锁定");
        } else if (authenticationException instanceof AccountExpiredException) {
            result.setMsg("账户过期");
        } else if (authenticationException instanceof CredentialsExpiredException) {
            result.setMsg("证书过期");
        } else {
            result.setMsg("登录失败");
        }
        return result;
    }


    @GetMapping("/admin")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String printAdmin() {
        return "如果你看见这句话，说明你有ROLE_ADMIN角色";
    }

    @GetMapping("/user")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_USER')")
    public String printUser() {
        return "如果你看见这句话，说明你有ROLE_USER角色";
    }
}
