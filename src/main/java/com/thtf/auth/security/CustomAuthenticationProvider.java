package com.thtf.auth.security;

import com.thtf.auth.exception.VerifyCodeException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/24 17:17
 * Version: v1.0
 * ========================
 */
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private StringRedisTemplate redisTemplate;


    @Value("${loginCode.prefix}")
    private String prefix;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 获取用户输入的用户名和密码
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        CustomWebAuthenticationDetails details = (CustomWebAuthenticationDetails) authentication.getDetails();

        String uuid = details.getUuid();
        String vCode = details.getVerifyCode();

        // 查询验证码
        String code = redisTemplate.opsForValue().get(prefix + uuid);

        // 清除验证码
        redisTemplate.delete(prefix + uuid);

        if (StringUtils.isBlank(code)) {
            throw new VerifyCodeException("验证码已过期");
        }
        if (StringUtils.isBlank(vCode) || !vCode.equalsIgnoreCase(code)) {
            throw new VerifyCodeException("验证码错误");
        }


        // userDetails为数据库中查询到的用户信息
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

        // 如果是自定义AuthenticationProvider，需要手动密码校验
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        if(!bCryptPasswordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("密码错误");
        }

        return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 这里不要忘记，和UsernamePasswordAuthenticationToken比较
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }


}
