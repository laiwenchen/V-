package org.sang.config;

import org.sang.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.DigestUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
    * 自定义用户认证逻辑*/
    @Autowired
    UserService userService;

    /**
     * 身份认证接口*/
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(new MyPasswordEncoder());
    }
    /**
     * http登录验证*/
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //都需要身份认证
        http.authorizeRequests()
//                该路径不用权限验证
                .antMatchers("/admin/category/all").authenticated()
                ///admin/**的URL都需要有超级管理员角色，如果使用.hasAuthority()方法来配置，需要在参数中加上ROLE_,如下.hasAuthority("ROLE_超级管理员")
                .antMatchers("/admin/**","/reg").hasRole("超级管理员")
                //其他的路径都是登录后即可访问
                .anyRequest().authenticated()
                .and()
                //表单登入的配置
                .formLogin()
                // 当http请求的url是/login时，进行我们自定义的登录逻辑
                .loginProcessingUrl("/login")
                //前端登录表单用户名别名, 从参数username中获取username参数取值
                .usernameParameter("username")
                //前端登录表单用户名别名, 从参数password中获取passowrd参数取值
                .passwordParameter("password")
                // permitAll中文意思是许可所有的：所有的都遵循上面的配置的意思
                .permitAll()
                //自定义登录的前端控制器
                .loginPage("/login_page")
                // 设置登录成功的跳转链接
                // .successForwardUrl("/home");
                // 通过successHandler处理器进行登录成功之后的逻辑处理
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    httpServletResponse.setContentType("application/json;charset=utf-8");
                    PrintWriter out = httpServletResponse.getWriter();
                    out.write("{\"status\":\"success\",\"msg\":\"登录成功\"}");
                    out.flush();
                    out.close();
                })
                // 设置登录失败的跳转链接
                // .failureForwardUrl("/errPage");
                // 通过failureHandler处理器进行登录失败之后的逻辑处理
                .failureHandler((httpServletRequest, httpServletResponse, e) -> {
                    httpServletResponse.setContentType("application/json;charset=utf-8");
                    PrintWriter out = httpServletResponse.getWriter();
                    out.write("{\"status\":\"error\",\"msg\":\"登录失败\"}");
                    out.flush();
                    out.close();
                })
                .and()
                //退出的配置
                .logout().permitAll()
                //关闭csrf
                .and().csrf().disable()
                //异常捕获
                .exceptionHandling()
                .accessDeniedHandler(getAccessDeniedHandler());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/blogimg/**","/index.html","/static/**");
    }

    @Bean
    AccessDeniedHandler getAccessDeniedHandler() {
        return new AuthenticationAccessDeniedHandler();
    }
}