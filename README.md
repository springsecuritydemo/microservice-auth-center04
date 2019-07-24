当我们登录失败的时候，SpringSecurity 帮我们跳转到了 `/login?error` URL，奇怪的是不管是控制台还是网页上都没有打印错误信息。
![](https://upload-images.jianshu.io/upload_images/11464886-8a702143d6654227.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

这是因为首先 `/login?error` 是SpringSecurity 默认的失败 URL，其次如果你不自己处理这个异常，这个异常时不会被处理的。

## 一、常见异常
我们先来列举下一些 SpringSecurity 中常见的异常：
- `UsernameNotFoundException` （用户不存在）
- `DisableException`（用户已被禁用）
- `BadCredentialsException`（坏的凭据）
- `LockedException`（账号锁定）
- `CerdentialsExpiredException`（证书过期）
- ...
以上列出的这些异常都是 `AuthenticationException` 的子类，然后我们看 SpringSecurity 是如何处理 `AuthenticationException` 异常的。

## 二、源码分析
SpringSecurity的异常处理是在过滤器中进行的，我们在 `AbastrctAuthenticationProcessingFilter` 中找到了对 `Authentication` 的处理：
- 在 doFilter() 中，捕获 AuthenticationException 异常，并交给 unsuccessfulAuthentication() 处理。
![](https://upload-images.jianshu.io/upload_images/11464886-3d79a9c35d16a904.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
- 在 `unsuccessfulAuthentication()` 中，转交给了 `SimpleUrlAuthenticationFailureHandler` 类的 `onAuthencicationFailure()` 处理。
![](https://upload-images.jianshu.io/upload_images/11464886-5bee808f9e6b76e3.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
- 在 onAuthenticationFailure() 中，首先判断有没有设置 `defaultFailureUrl`。

   a. 如果没有设置，直接返回 401 错误，即 `HttpStatus.UNAUTHORIZED` 的值。
   b. 如果设置了，首先执行 `saveException()` 方法。然后判断 `forwardToDestination` 是否为服务器调整，默认使用重定向即客户端跳转。

![](https://upload-images.jianshu.io/upload_images/11464886-db57d1e842f65ea2.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

- 在 saveException() 方法中，首先判断 `forwardToDestination`，如果使用服务器跳转则写入`Request`，客户端跳转则写入 `Session`。写入名为 `WebAttributes.AUTHENTICATION_EXCEPTION` 常量对应值`SPRING_SECURITY_LAST_EXCEPTION`，值为 `AuthenticationException` 对象。
![](https://upload-images.jianshu.io/upload_images/11464886-97e8cb95c2b433fc.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

至此 SpringSecurity 完成了异常处理，总结下流程：

–> AbstractAuthenticationProcessingFilter`.doFilter()`
–> AbstractAuthenticationProcessingFilter.`unsuccessfulAuthentication()`
–> SimpleUrlAuthenticationFailureHandler.`onAuthenticationFailure()`
–> SimpleUrlAuthenticationFailureHandler.`saveException()`

## 三、处理异常
上面通过源码看着挺复杂，但真正处理起来SpringSecurity为我们提供了方便的方式，我们只需要指定错误的url，然后在该方法中对异常进行处理即可。
- 指定错误url ，在`WebSecurityConfig` 中添加 `.failureUrl("/login/error")`：
```
 @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // 如果有允许匿名的url，填在下面
//                .antMatchers().permitAll()
                .anyRequest().authenticated()
                .and()
                // 设置登陆页
                .formLogin().loginPage("/login")
                // 设置登陆成功url
                .defaultSuccessUrl("/").permitAll()
                // 设置登录失败url
                .failureUrl("/login/error")
                // 自定义登陆用户名和密码参数，默认为username和password
//                .usernameParameter("username")
//                .passwordParameter("password")
                .and()
                .logout().permitAll()
                // 自动登录
                .and().rememberMe()
                .tokenRepository(persistentTokenRepository())
                // 有效时间，单位：s
                .tokenValiditySeconds(60)
                .userDetailsService(userDetailsService);

        // 关闭CSRF跨域
        http.csrf().disable();
    }
```
- 在 Controller 中编写 `loginError`方法完成异常处理操作：
```
 @GetMapping("/login/error")
    @ResponseBody
    public Result loginError(HttpServletRequest request) {
        AuthenticationException authenticationException = (AuthenticationException) request.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        log.info("authenticationException={}", authenticationException);
        Result result = new Result();
        result.setCode(201);

        if (authenticationException instanceof UsernameNotFoundException || authenticationException instanceof BadCredentialsException) {
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
```

## 四、运行项目
首先我们修改 `CustomUserDetailsService` `loadUserByUsername()` 方法的返回值:
![](https://upload-images.jianshu.io/upload_images/11464886-67f2c037c3afebcb.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

1. 输入错误的用户名或密码：
![](https://upload-images.jianshu.io/upload_images/11464886-cf4fcc8d2733ef51.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
2. 修改返回值：enable 为 false
![](https://upload-images.jianshu.io/upload_images/11464886-db8c5a23787f7f58.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![](https://upload-images.jianshu.io/upload_images/11464886-1b413975a3db5a9f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
3. 修改返回值：accountNonExpired 为 false
![](https://upload-images.jianshu.io/upload_images/11464886-e9eeedaa1c456014.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![](https://upload-images.jianshu.io/upload_images/11464886-98bb1b606fb5fd62.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
4. 修改返回值：credentialsNonExpired 为 false
![](https://upload-images.jianshu.io/upload_images/11464886-b7d500ecea672441.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![](https://upload-images.jianshu.io/upload_images/11464886-012fb669fa01ae6f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
5. 修改返回值：accountNonLocked 为 false
![](https://upload-images.jianshu.io/upload_images/11464886-720b9a490c90b419.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![](https://upload-images.jianshu.io/upload_images/11464886-ef515a5c2c75a152.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 五、存在问题
细心的同学再完成上面功能是会发现，当我们输入的用户名不存在时，不会抛出`UserNameNotFoundException`，而是抛出 `BadCredentialsException`这个异常，如果有需要区分 用户名不存在和密码错误的，可参考[https://blog.csdn.net/wzl19870309/article/details/70314085](https://blog.csdn.net/wzl19870309/article/details/70314085)。



