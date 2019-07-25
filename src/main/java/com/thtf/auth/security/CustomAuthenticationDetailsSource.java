package com.thtf.auth.security;

        import org.springframework.security.authentication.AuthenticationDetailsSource;
        import org.springframework.security.web.authentication.WebAuthenticationDetails;
        import org.springframework.stereotype.Component;

        import javax.servlet.http.HttpServletRequest;

/**
 * ========================
 * 该接口用于在Spring Security登录过程中对用户的登录信息的详细信息进行填充
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/24 17:06
 * Version: v1.0
 * ========================
 */
@Component("authenticationDetailsSource")
public class CustomAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {

    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest request) {
        return new CustomWebAuthenticationDetails(request);
    }
}
