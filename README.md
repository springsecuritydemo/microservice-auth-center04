无论是在生活还是在 WEB 应用开发中，安全一直是非常重要的一个方面。安全虽然属于应用的非功能需求，但是应该在应用开启初期就考虑进来。如果在应用开发的后期才考虑安全问题，就可能陷入一个两难的境地：

一方面，应用存在严重的安全漏洞，无法满足用户的要求，并可能造成用户的隐私数据被攻击者窃取；

两一方面，应用的基本架构已经确定，要修复安全漏洞，可能要对系统的架构做出比较重大的调整，进而需要更多的开发时间，影响整个项目的进度。所以，从应用开发的前期就应该把安全相关的因素考虑进来，并在整个系统开发过程中应用。

## 一、SpringSecurity简介
SpringSecurity 是基于Spring 提供声明式安全保护的安全性框架。SpringSecurity提供了完整的安全性解决方案，能够在**Web请求级别**和**方法调用级别**处理身份**认证**和**授权**

###1.1 SpringSecurity 如何解决安全性问题 ？
SpringSecurity从两个角度来解决安全性问题：
- **使用 Servlet 规范中的 Filter**： 保护web请求并限制 URL 级别的访问；
- **使用 Spring AOP 保护方法调用**：借助于动态代理和使用通知，确保只有具备适当权限的用户才能访问安全保护的方法。

###1.2 SpringSecurity 模块划分
Spring Security被分为了11个模块：
|模块	| 描述|
|--|--|
|ACL(access control list)|	支持通过访问控制列表（ACL）为域对象提供安全性|
|切面（Aspects）	|当使用Spring Security注解时，会使用基于AspectJ的切面，而非标准的AOP|
|CAS(Central Authentication Service)客户端|	提供与Jasig的中心认证服务（CAS）进行集成的功能|
|配置（Configuratiion）*	|包含通过XML和Java配置Spring Security的功能支持|
|核心（Core）　　　　  *|	提供Spring Security基本库|
|加密（Cryptography）|	提供了加密和密码编码的功能|
|LDAP	|支持基于LDAP进行认证|
|OpenID	|支持使用OpenID进行集中式认证|
|Remoting|	提供了对Spring Remoting的支持|
|标签库（Tag Library）|	Spring Security的JSP标签库|
|Web|	提供了Spring Security基于Filter的Web安全性支持|

接下来我们就使用SpringBoot + SpringSecurity完成入门程序。

## 二、SpringBoot整合SpringSecurity

### 2.1 导入依赖
导入 spring-boot-starter-security 依赖，在 SpringBoot 2.0 环境下默认使用的是 5.0 版本。

```
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-web</artifactId>
</dependency>

<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-test</artifactId>
	<scope>test</scope>
</dependency>

<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>

<dependency>
	<groupId>org.mybatis.spring.boot</groupId>
	<artifactId>mybatis-spring-boot-starter</artifactId>
	<version>1.3.1</version>
</dependency>

<dependency>
	<groupId>mysql</groupId>
	<artifactId>mysql-connector-java</artifactId>
</dependency>
<dependency>
     <groupId>com.alibaba</groupId>
     <artifactId>druid-spring-boot-starter</artifactId>
     <version>1.1.10</version>
</dependency>
 <dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <version>1.16.16</version>
 </dependency>
```
### 2.2 创建数据库表
一般权限控制有三层，即：`用户`<–>`角色`<–>`权限`，用户与角色是多对多，角色和权限也是多对多。这里我们先暂时不考虑权限，只考虑`用户`<–>`角色`。
这里为了测试，表结构简单设计，后续可以根据业务添加先关字段。

数据库：Mysql 5.6
创建表结构：
```
-- 用户表
CREATE TABLE `sys_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- 角色表
CREATE TABLE `sys_role` (
  `id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- 用户-角色关系表
CREATE TABLE `sys_user_role` (
  `user_id` int(11) NOT NULL,
  `role_id` int(11) NOT NULL,
  PRIMARY KEY (`user_id`,`role_id`),
  KEY `fk_role_id` (`role_id`),
  CONSTRAINT `fk_role_id` FOREIGN KEY (`role_id`) REFERENCES `sys_role` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_user_id` FOREIGN KEY (`user_id`) REFERENCES `sys_user` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```
初始化数据：

```
INSERT INTO `sys_role` VALUES ('1', 'ROLE_ADMIN');
INSERT INTO `sys_role` VALUES ('2', 'ROLE_USER');

INSERT INTO `sys_user` VALUES ('1', 'admin', '123');
INSERT INTO `sys_user` VALUES ('2', 'pyy', '123');

INSERT INTO `sys_user_role` VALUES ('1', '1');
INSERT INTO `sys_user_role` VALUES ('2', '2');
```
>**注意：**这里的权限格式为`ROLE_XXX`，是Spring Security规定的，不要乱起名字哦。

### 2.3 准备页面
因为是实例程序，这里页面简单设计，只用于登录的 `login.html` 以及用户登录成功后跳转的 `index.html`，将其放置在工程 `resources/static` 目录下：

登录login.html:
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登陆</title>
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
        <button type="submit">立即登陆</button>
    </div>
</form>
</body>
</html>
```
>**注意：**用户的登陆认证是由Spring Security进行处理的，请求路径默认为`/login`，用户名字段默认为`username`，密码字段默认为`password`

首页index.html:
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
    <h1>登陆成功</h1>
    <a href="/admin">检测ROLE_ADMIN角色</a>
    <a href="/user">检测ROLE_USER角色</a>
    <button onclick="window.location.href='/logout'">退出登录</button>
</body>
</html>
```

### 2.4 配置application.yml
```
server:
  port: 9000
  servlet:
    context-path: /auth
spring:
  application:
    name: microservice-auth-center
  datasource:
    druid:
      url: jdbc:mysql://localhost:3306/auth_center?characterEncoding=utf-8
      username: root
      password: 123456
      driverClassName: com.mysql.jdbc.Driver
      initialSize: 5  #初始建立连接数量
      minIdle: 5  #最小连接数量
      maxActive: 20 #最大连接数量
      maxWait: 10000  #获取连接最大等待时间，毫秒
      testOnBorrow: true #申请连接时检测连接是否有效
      testOnReturn: false #归还连接时检测连接是否有效
      timeBetweenEvictionRunsMillis: 60000 #配置间隔检测连接是否有效的时间（单位是毫秒）
      minEvictableIdleTimeMillis: 300000 #连接在连接池的最小生存时间（毫秒）
      
mybatis:
  configuration:
    map-underscore-to-camel-case: true #开启Mybatis下划线命名转驼峰命名
```
### 2.5 创建实体类、DAO、Service和Controller

实体类：
- SysUser：
```
@Data
public class SysUser implements Serializable{
    private static final long serialVersionUID = -2836223054703407171L;

    private Integer id;

    private String name;

    private String password;
}
```
- SysRole：
```
@Data
public class SysRole implements Serializable {
    private static final long serialVersionUID = 7510551869226022669L;

    private Integer id;

    private String name;
}
```
- SysUserRole：
```
@Data
public class SysUserRole implements Serializable{
    private static final long serialVersionUID = -3256750757278740295L;

    private Integer userId;

    private Integer roleId;
}
```

DAO：

- SysUserMapper：
```
@Mapper
public interface SysUserMapper {

    @Select("SELECT * FROM sys_user WHERE id = #{id}")
    SysUser selectById(Integer id);

    @Select("SELECT * FROM sys_user WHERE name = #{name}")
    SysUser selectByName(String name);
}
```
- SysRoleMapper：
```
@Mapper
public interface SysRoleMapper {

    @Select("SELECT * FROM sys_role WHERE id = #{id}")
    SysRole selectById(Integer id);
}
```
- SysUserRoleMapper：
```
@Mapper
public interface SysUserRoleMapper {

    @Select("SELECT * FROM sys_user_role WHERE user_id = #{userId}")
    List<SysUserRole> listByUserId(Integer userId);
}
```
Service：
- SysUserService：
```
@Service
public class SysUserService {

    @Autowired
    private SysUserMapper userMapper;

    public SysUser selectById(Integer id) {
        return userMapper.selectById(id);
    }

    public SysUser selectByName(String name) {
        return userMapper.selectByName(name);
    }
}
```
- SysRoleService：
```
@Service
public class SysRoleService {

    @Autowired
    private SysRoleMapper roleMapper;

    public SysRole selectById(Integer id){
        return roleMapper.selectById(id);
    }
}
```
- SysUserRoleService：
```
@Service
public class SysUserRoleService {

    @Autowired
    private SysUserRoleMapper userRoleMapper;

    public List<SysUserRole> listByUserId(Integer userId) {
        return userRoleMapper.listByUserId(userId);
    }
}
```
Controller：
```
@Controller
public class LoginController {
    private Logger logger = LoggerFactory.getLogger(LoginController.class);

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
```
>**注意**：如代码所示：
>- 获取当前登录用户：`SecurityContextHolder.getContext().getAuthentication()`
>- `@PreAuthorize` 用于判断用户是否有指定权限，没有就不能访问

### 三、配置SpringSecurity
### 3.1 UserDetailService
首先，我们需要自定义 `UserDetailService`， 将用户信息和权限注入进来。

我们需要重写 `loadUserByUsername` 方法，参数是用户输入的 用户名。 返回值是 `UserDetails`，这是一个接口，一般使用它的子类 `org.springframework.security.core.userdetails.User`。
```
public class User implements UserDetails, CredentialsContainer {
    private static final long serialVersionUID = 500L;
    private static final Log logger = LogFactory.getLog(User.class);
    private String password;
    private final String username;
    private final Set<GrantedAuthority> authorities;
    private final boolean accountNonExpired;
    private final boolean accountNonLocked;
    private final boolean credentialsNonExpired;
    private final boolean enabled;

    public User(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        this(username, password, true, true, true, true, authorities);
    }

    public User(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        if(username != null && !"".equals(username) && password != null) {
            this.username = username;
            this.password = password;
            this.enabled = enabled;
            this.accountNonExpired = accountNonExpired;
            this.credentialsNonExpired = credentialsNonExpired;
            this.accountNonLocked = accountNonLocked;
            this.authorities = Collections.unmodifiableSet(sortAuthorities(authorities));
        } else {
            throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
        }
    }
```
这里我们暂时只关注三个参数：用户名、密码和权限集。其它属性暂时使用默认值。

>实际情况下，大多将 DAO 中的 User 类继承 `org.springframework.security.core.userdetails.User` 返回。

CustomUserDetailsService：
```
@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private SysUserService userService;

    @Autowired
    private SysRoleService roleService;

    @Autowired
    private SysUserRoleService userRoleService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        // 从数据库中取出用户信息
        SysUser user = userService.selectByName(username);

        // 判断用户是否存在
        if(user == null) {
            throw new UsernameNotFoundException("用户名不存在");
        }

        // 添加权限
        List<SysUserRole> userRoles = userRoleService.listByUserId(user.getId());
        for (SysUserRole userRole : userRoles) {
            SysRole role = roleService.selectById(userRole.getRoleId());
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }

        // 返回UserDetails实现类
        return new User(user.getName(), user.getPassword(), authorities);
    }

}
```

### 3.2 WebSecurityConfig
Spring Security默认是禁用注解的，要想开启注解， 需要在继承`WebSecurityConfigurerAdapter`的类上加`@EnableGlobalMethodSecurity`注解， 来判断用户对某个控制层的方法是否具有访问权限 

例如：上面代码方法前不加@preAuthorize注解，意味着所有用户都能访问方法，如果加上注解，表示只要具备指定角色的用户才有权限访问。

**@EnableGlobalMethodSecurity详解**：
- `@EnableGlobalMethodSecurity(securedEnabled=true)` 开启`@Secured` 注解过滤权限
- `@EnableGlobalMethodSecurity(jsr250Enabled=true)`开启`@RolesAllowed `注解过滤权限 
- `@EnableGlobalMethodSecurity(prePostEnabled=true)` 使用表达式实现方法级别的安全性 ，4个注解可用：
  1. `@PreAuthorize` 在方法调用之前,基于表达式的计算结果来限制对方法的访问
   2. `@PostAuthorize` 允许方法调用,但是如果表达式计算结果为false,将抛出一个安全性异常
   3. `@PostFilter` 允许方法调用,但必须按照表达式来过滤方法的结果
  4. `@PreFilter `允许方法调用,但必须在进入方法之前过滤输入值

首先，我们将自定义的 `userDetailsService` 注入进来，在 `configure()` 方法中使用 `auth.userDetailsService()` 方法替换掉默认的 `userDetailsService `。

这里我们还指定了密码的加密模式（5.0版本强制要求设置），我们采用SpringSecurity提供的加密模式：`BCryptPasswordEncoder`，它帮我们实现了`PasswordEncoder`，当然也可以自定义加密模式。

```
package com.thtf.auth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/23 11:10
 * Version: v1.0
 * ========================
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // 如果有允许匿名的url，填在下面
//                .antMatchers().permitAll()
                .anyRequest().authenticated()
                .and()
                // 设置登陆页
                .formLogin().loginPage("/login")
                // 设置登陆成功页
                .defaultSuccessUrl("/").permitAll()
                // 自定义登陆用户名和密码参数，默认为username和password
//                .usernameParameter("username")
//                .passwordParameter("password")
                .and()
                .logout().permitAll();

        // 关闭CSRF跨域
        http.csrf().disable();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 设置拦截忽略文件夹，可以对静态资源放行
        web.ignoring().antMatchers("/css/**", "/js/**");
    }
}
```

## 四、运行测试
启动工程之前，由于数据库用户表的密码初始化的是明文，这里我们需要使用SpringSecurity 提供的加密工具类对密码进行重新加密修改：
加密类：
```
public class SpringSecurityUtil {
    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        String password = bCryptPasswordEncoder.encode("123");

        System.out.println(password);
    }
}
```
加密后密文：`$2a$10$MVN49jp9CwX1M5.8.Sw1NeyrshO.g.zZ7usZ/63B4qbuZxh3NOriG`
![](https://upload-images.jianshu.io/upload_images/11464886-bb1cb730f5a9d7d0.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

注：随机盐加密所以两次加密后结果不一样

**启动工程：**
>ROLE_ADMIN 账户：用户名 admin，密码 123
ROLE_USER 账户：用户名 pyy，密码 123


- 使用 ROLE_ADMIN 账号登录：
![](https://upload-images.jianshu.io/upload_images/11464886-0ebba576c232941d.gif?imageMogr2/auto-orient/strip)


- 使用 ROLE_USER 账号登录：
![](https://upload-images.jianshu.io/upload_images/11464886-62ac78d01e5ab0c1.gif?imageMogr2/auto-orient/strip)

到此，我们的SpringBoot + SpringSecurity 入门案例已经讲解完毕，接下来我们将使用SpringSecurity 完成 用户登录 - 自动登录功能。