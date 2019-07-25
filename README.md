通过之前文章的学习，我们已经基本上掌握了SpringSecurity的基本流程。你会发现，真正的login请求时有SpringSecurity帮我们处理的，那么我们如何实现自定义表单登录呢，必须添加一个验证码等。
## 一、添加验证码
我们这里为了方便，直接从百度找了个生成验证码的代码，你也可以使用自己项目中的验证码生成工具。
### 1.1 生成验证码工具类
```
public class VerifyCodeUtils {

    //使用到Algerian字体，系统里没有的话需要安装字体，字体只显示大写，去掉了1,0,i,o几个容易混淆的字符
    public static final String VERIFY_CODES = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static Random random = new Random();


    /**
     * 使用系统默认字符源生成验证码
     * @param verifySize	验证码长度
     * @return
     */
    public static String generateVerifyCode(int verifySize){
        return generateVerifyCode(verifySize, VERIFY_CODES);
    }
    /**
     * 使用指定源生成验证码
     * @param verifySize	验证码长度
     * @param sources	验证码字符源
     * @return
     */
    public static String generateVerifyCode(int verifySize, String sources){
        if(sources == null || sources.length() == 0){
            sources = VERIFY_CODES;
        }
        int codesLen = sources.length();
        Random rand = new Random(System.currentTimeMillis());
        StringBuilder verifyCode = new StringBuilder(verifySize);
        for(int i = 0; i < verifySize; i++){
            verifyCode.append(sources.charAt(rand.nextInt(codesLen-1)));
        }
        return verifyCode.toString();
    }

    /**
     * 输出指定验证码图片流
     * @param w
     * @param h
     * @param os
     * @param code
     * @throws IOException
     */
    public static void outputImage(int w, int h, OutputStream os, String code) throws IOException{
        int verifySize = code.length();
        BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Random rand = new Random();
        Graphics2D g2 = image.createGraphics();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,RenderingHints.VALUE_ANTIALIAS_ON);
        Color[] colors = new Color[5];
        Color[] colorSpaces = new Color[] { Color.WHITE, Color.CYAN,
                Color.GRAY, Color.LIGHT_GRAY, Color.MAGENTA, Color.ORANGE,
                Color.PINK, Color.YELLOW };
        float[] fractions = new float[colors.length];
        for(int i = 0; i < colors.length; i++){
            colors[i] = colorSpaces[rand.nextInt(colorSpaces.length)];
            fractions[i] = rand.nextFloat();
        }
        Arrays.sort(fractions);

        g2.setColor(Color.GRAY);// 设置边框色
        g2.fillRect(0, 0, w, h);

        Color c = getRandColor(200, 250);
        g2.setColor(c);// 设置背景色
        g2.fillRect(0, 2, w, h-4);

        //绘制干扰线
        Random random = new Random();
        g2.setColor(getRandColor(160, 200));// 设置线条的颜色
        for (int i = 0; i < 20; i++) {
            int x = random.nextInt(w - 1);
            int y = random.nextInt(h - 1);
            int xl = random.nextInt(6) + 1;
            int yl = random.nextInt(12) + 1;
            g2.drawLine(x, y, x + xl + 40, y + yl + 20);
        }

        // 添加噪点
        float yawpRate = 0.05f;// 噪声率
        int area = (int) (yawpRate * w * h);
        for (int i = 0; i < area; i++) {
            int x = random.nextInt(w);
            int y = random.nextInt(h);
            int rgb = getRandomIntColor();
            image.setRGB(x, y, rgb);
        }

        shear(g2, w, h, c);// 使图片扭曲

        g2.setColor(getRandColor(100, 160));
        int fontSize = h-4;
        Font font = new Font("Algerian", Font.ITALIC, fontSize);
        g2.setFont(font);
        char[] chars = code.toCharArray();
        for(int i = 0; i < verifySize; i++){
            AffineTransform affine = new AffineTransform();
            affine.setToRotation(Math.PI / 4 * rand.nextDouble() * (rand.nextBoolean() ? 1 : -1), (w / verifySize) * i + fontSize/2, h/2);
            g2.setTransform(affine);
            g2.drawChars(chars, i, 1, ((w-10) / verifySize) * i + 5, h/2 + fontSize/2 - 10);
        }

        g2.dispose();
        ImageIO.write(image, "jpg", os);
    }

    private static Color getRandColor(int fc, int bc) {
        if (fc > 255)
            fc = 255;
        if (bc > 255)
            bc = 255;
        int r = fc + random.nextInt(bc - fc);
        int g = fc + random.nextInt(bc - fc);
        int b = fc + random.nextInt(bc - fc);
        return new Color(r, g, b);
    }

    private static int getRandomIntColor() {
        int[] rgb = getRandomRgb();
        int color = 0;
        for (int c : rgb) {
            color = color << 8;
            color = color | c;
        }
        return color;
    }

    private static int[] getRandomRgb() {
        int[] rgb = new int[3];
        for (int i = 0; i < 3; i++) {
            rgb[i] = random.nextInt(255);
        }
        return rgb;
    }

    private static void shear(Graphics g, int w1, int h1, Color color) {
        shearX(g, w1, h1, color);
        shearY(g, w1, h1, color);
    }

    private static void shearX(Graphics g, int w1, int h1, Color color) {

        int period = random.nextInt(2);

        boolean borderGap = true;
        int frames = 1;
        int phase = random.nextInt(2);

        for (int i = 0; i < h1; i++) {
            double d = (double) (period >> 1)
                    * Math.sin((double) i / (double) period
                    + (6.2831853071795862D * (double) phase)
                    / (double) frames);
            g.copyArea(0, i, w1, 1, (int) d, 0);
            if (borderGap) {
                g.setColor(color);
                g.drawLine((int) d, i, 0, i);
                g.drawLine((int) d + w1, i, w1, i);
            }
        }

    }

    private static void shearY(Graphics g, int w1, int h1, Color color) {

        int period = random.nextInt(40) + 10; // 50;

        boolean borderGap = true;
        int frames = 20;
        int phase = 7;
        for (int i = 0; i < w1; i++) {
            double d = (double) (period >> 1)
                    * Math.sin((double) i / (double) period
                    + (6.2831853071795862D * (double) phase)
                    / (double) frames);
            g.copyArea(i, 0, 1, h1, 0, (int) d);
            if (borderGap) {
                g.setColor(color);
                g.drawLine(i, (int) d, i, 0);
                g.drawLine(i, (int) d + h1, i, h1);
            }
        }
    }
}
```
### 1.2 编写Redis配置、封装结果集和生成图片接口
我们将生成的验证码存入到服务器的 Session 对象中，但如果你的项目是分布式项目或者是App项目，这里就不能存入到Session中，可以考虑使用 Redis 存储。我们采用Redis 存储方案。
添加redis依赖包：
```
        <!-- redis -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
```
添加redis和图片验证码失效时间：
```
...
  redis:
    #数据库索引
    database: 0
    host: 127.0.0.1
    port: 6379
    password:
    #连接超时时间
    timeout: 5000
loginCode:
  expiration: 1 #登录验证码过期时间，单位 分钟
  prefix: login_code #验证码redis的key值前缀
```
编写图片结果集：
```
@Data
@AllArgsConstructor
public class ImgResult {
    private String img;
    private String uuid;
}
```
编写获取验证码接口：
```
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
        redisTemplate.opsForValue().set(prefix + uuid,verifyCode, expiration, TimeUnit.MINUTES);
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
```
这里采用 `Base64`格式的图片返回，使用`Hutool`依赖包完成Base64转换：
```
        <!--工具包-->
        <dependency>
            <groupId>cn.hutool</groupId>
            <artifactId>hutool-all</artifactId>
            <version>4.5.11</version>
        </dependency>
```
### 1.3 修改login.html
在原来的 login 页面集成上加入 验证码字段：
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登陆</title>
    <script src="js/jquery-3.4.1.min.js"></script>
</head>
<body>
<h1>登陆</h1>
<form method="post" action="/login">
    <div>
        用户名：<input type="text" name="username">
    </div>
    <div>
        密　码：<input type="password" name="password">
    </div>
    <div>
        验证码：<input type="text" class="form-control" name="verifyCode" required="required" placeholder="验证码">
        <input id="uuid" type="hidden" name="uuid" />
        <img  id="vCode" title="看不清，请点我" onclick="getVerifyCode()" onmouseover="mouseover(this)" />
    </div>
    <div>
        <label><input type="checkbox" name="remember-me"/>自动登录</label>
    </div>
    <div>
        <button type="submit">立即登陆</button>
    </div>
</form>

<script>
    $(function() {
        getVerifyCode();
    })

    function getVerifyCode() {
        var url = "/vCode?" + Math.random();
        $.ajax({
            //请求方式
            type : "GET",
            //请求的媒体类型
            contentType: "application/json;charset=UTF-8",
            //请求地址
            url : url,
            //请求成功
            success : function(result) {
                console.log(result);
                $("#uuid").val(result.uuid);
                $("#vCode").attr("src","data:image/png;base64," + result.img);
            },
            //请求失败，包含具体的错误信息
            error : function(e){
                console.log(e.status);
                console.log(e.responseText);
            }
        });
    }

    function mouseover(obj) {
        obj.style.cursor = "pointer";
    }
</script>

</body>
</html>
```
### 1.4 添加匿名访问 URL（放行 验证码请求）
在 `WebSecurityConfig` 中允许 验证码请求匿名访问，不然没有登录就没办法获取验证码（死循环了）。
```
    @Autowired
    private StringRedisTemplate redisTemplate;

    @Value("${loginCode.prefix}")
    private String prefix;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // 如果有允许匿名的url，填在下面
                .antMatchers("/vCode").permitAll()
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
                // 添加图片验证码过滤器
                .addFilterBefore(new VerifyFilter(redisTemplate, prefix), UsernamePasswordAuthenticationFilter.class)
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
这样验证码就加好了。
### 1.5 运行程序
![](https://upload-images.jianshu.io/upload_images/11464886-796f4fc43f24e941.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 二、验证码验证
验证方式：
- **AJAX 验证**
- **过滤器验证**
- **Spring Security 验证**
接下来我们分别针对这几种验证方式做讲解。

### 2.1 AJAX验证
使用 AJAX 方式验证和我们 Spring Security 框架就没有任何关系了，其实就是表单提交前先发个 HTTP 请求验证验证码，本篇不再赘述。有兴趣的同学可以自己实现。

### 2.2 过滤器验证
使用过滤器验证的思路： **在SpringSecurity 处理登录验证请求前，先验证验证码，如果正确，放行；如果不正确，抛出异常。**

具体实现步骤如下：
#### **第一步**：编写自定义验证码异常，继承`AuthenticationException`抽象类
```
public class VerifyCodeException extends AuthenticationException {

    public VerifyCodeException(String msg) {
        super(msg);
    }

    public VerifyCodeException(String msg, Throwable t) {
        super(msg, t);
    }
}
```
#### **第二步**：编写验证码过滤器
自定义一个过滤器，实现 `OncePerRequestFilter`（用于防止多次执行Filter的；也就是说一次请求只会走一次拦截器链） ，在 `isProtectedUrl()` 方法中拦截 POST 方式的` /login` 请求。

在逻辑处理中从 request 中取出验证码，并进行验证，如果验证成功，放行；验证失败，手动抛出异常。
```
public class VerifyFilter extends OncePerRequestFilter{

    private static final PathMatcher pathMatcher = new AntPathMatcher();

    private StringRedisTemplate stringRedisTemplate;

    private String prefix;

    public VerifyFilter() {}

    public VerifyFilter(StringRedisTemplate stringRedisTemplate, String prefix) {
        this.stringRedisTemplate = stringRedisTemplate;
        this.prefix = prefix;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 拦截 /login的POST请求
        if(isProtectedUrl(request)) {
            String uuid = request.getParameter("uuid"); // 图片验证码的 key
            String vCode = request.getParameter("verifyCode");// 图片验证码的 value

            if(!validateVerify(request, uuid, vCode)) {
                //手动设置异常
                request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION",new VerifyCodeException("验证码输入错误"));
                // 转发到错误Url
                request.getRequestDispatcher("/login/error").forward(request,response);
            } else {
                filterChain.doFilter(request,response);
            }
        } else {
            filterChain.doFilter(request,response);
        }
    }

    /**
     * 验证验证码合法性
     * @param uuid  验证key
     * @param vCode 验证值
     * @return
     */
    private boolean validateVerify(HttpServletRequest request, String uuid, String vCode) {
        // 查询验证码
        String code = stringRedisTemplate.opsForValue().get(prefix + uuid);

        // 清除验证码
        stringRedisTemplate.delete(prefix + uuid);

        if (StringUtils.isBlank(code)) {
            //手动设置异常
            request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new VerifyCodeException("验证码已过期"));
            return false;
        }
        if (StringUtils.isBlank(vCode) || !vCode.equalsIgnoreCase(code)) {
            request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new VerifyCodeException("验证码错误"));
            return false;
        }

        logger.info("验证码：" + code + "用户输入：" + vCode);
        return true;
    }

    // 拦截 /login的POST请求
    private boolean isProtectedUrl(HttpServletRequest request) {
        return "POST".equals(request.getMethod()) && pathMatcher.match("/login", request.getServletPath());
    }

}

```
#### **第三步**：修改` loginError() `方法，添加 图片验证码异常处理 ：
特别注意：这里不要指定请求方式，而使用：`@RequestMapping("/login/error")`，这里之前我做这个测试，发现SpringSecurity 默认错误调整使用的是 GET 方式，这里我们手动通过 `request.getDispatcher("/login/error").forward() `使用的是 post方式。所以这里一定记得修改注解方式为 `@RequestMapping()`，不然你会发现怎么也不成功。
![](https://upload-images.jianshu.io/upload_images/11464886-53593974af80dc0b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

```
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
```
#### **第四步**：注入过滤器
修改 `WebSecurityConfig` 中 `configure()` 方法，添加一个 `addFilterBefore()`，具有两个参数，作用是在参数二之前执行参数一指定的过滤器。

SpringSecurity 对于用户名/密码登录方式是通过 `UsernamePasswordAuthenticationFilter` 处理的，所以我们在它之前执行自定义验证码过滤器即可。
```
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // 如果有允许匿名的url，填在下面
                .antMatchers("/vCode").permitAll()
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
                // 添加图片验证码过滤器
                .addFilterBefore(new VerifyFilter(redisTemplate), UsernamePasswordAuthenticationFilter.class)
                .logout().permitAll()
                // 自动登录
                .and().rememberMe()
                .tokenRepository(persistentTokenRepository())
                // 有效时间，单位：s
                .tokenValiditySeconds(60)
                .userDetailsService(userDetailsService);

        // 关闭CSRF跨域
        http.csrf().disable();
```
#### **第五步**：运行程序
![](https://upload-images.jianshu.io/upload_images/11464886-547b889e73adf15a.gif?imageMogr2/auto-orient/strip)

上面我们使用过滤器实现了验证功能，但是其他它和AJAX 验证差别不大。

- AJAZ 验证是在登录提交前发送一个异步请求，请求返回成功就提交登录；失败就不提交登录。
- 过滤器是先验证验证码，验证成功就让 SpringSecurity 验证用户名和密码；验证失败则抛出异常。

如果我们要做的需求是用户登录时需要多个验证字段，不单单是用户名和密码，那么使用过滤器会让逻辑变得复杂，而这里我们通过另外一种方式来完整验证逻辑。

### 2.3 SpringSecurity验证

#### **第一步**：自定义 `WebAuthenticationDetails` 类:
我们知道SpringSecurity 默认情况下只会处理用户名和密码信息。
 >`WebAuthenticationDetails`: 该类提供了获取用户登录时携带的额外信息的功能，默认提供了 remoteAddress 与 sessionId 信息。
```
public class WebAuthenticationDetails implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	// ~ Instance fields
	// ================================================================================================

	private final String remoteAddress;
	private final String sessionId;
    ...
```
这时候我们就要自定义 `CustomWebAuthenticationDetails`类，并在其中加入我们的验证码字段：
```
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
```
在这个类我们增加两个属性：uuid 和 verifyCode。

#### **第二步**：配置 `AuthenticationDetailsSource`
自定义了 `WebAuthenticationDetails`，我们需要将其放入到 `AuthenticationDetailsSource` 中替换原来的 `WebAuthenticationDetails` 对象，所以我们还得实现自定义 `AuthenticationDetailsSource`：
```
package com.thtf.auth.security;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

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
```
#### **第三步**：将 `CustomAuthenticationDetailsSource ` 注入到SpringSecurity中。
修改 `WebSecurityConfig`，在 `configure()` 方法中使用 `authenticationDetailsSource(authenticationDetailsSource)`方法来指定它，替换默认的`AuthenticationDetailsSource`对象。
```
    @Autowired
    private AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // 如果有允许匿名的url，填在下面
                .antMatchers("/vCode").permitAll()
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
                // 指定authenticationDetailsSource
                .authenticationDetailsSource(authenticationDetailsSource)
                .and()
                // 添加图片验证码过滤器
                //.addFilterBefore(new VerifyFilter(redisTemplate, prefix), UsernamePasswordAuthenticationFilter.class)
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
#### **第四步**：自定义 `AuthenticationProvider`
上面我们通过自定义 `WebAuthenticationDetails`和`AuthenticationDetailsSource`将验证码key、验证码值和用户名、密码一起带入了Spring Security中，下面我们需要将它取出来。

这里需要我们自定义`AuthenticationProvider`，需要注意：**如果是我们自己实现`AuthenticationProvider`，那么我们就需要自己做密码校验了**。
```
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

```
#### **第五步**： 在 WebSecurityConfig 中注入 `CustomAuthenticationProvider`:
```
@Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());
        auth.authenticationProvider(customAuthenticationProvider);
    }
```

#### **第六步**：运行程序
![](https://upload-images.jianshu.io/upload_images/11464886-9666cf7b2fb11f9d.gif?imageMogr2/auto-orient/strip)

是不是更复杂了O(∩_∩)O哈哈~