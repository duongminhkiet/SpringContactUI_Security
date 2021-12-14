package com.example.demo.config.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)// to enable for adding @Secured at controller
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
	
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	@Autowired
    PasswordEncoder passwordEncoder;
 
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
        .passwordEncoder(passwordEncoder)
        .withUser("user").password(passwordEncoder.encode("123")).roles("USER")
        .and()
        .withUser("admin").password(passwordEncoder.encode("123")).roles("USER", "ADMIN");
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
    	
        http.authorizeRequests()
        .antMatchers("/login1")//controller
            .permitAll()
        .antMatchers("/**")
            .hasAnyRole("ADMIN", "USER")
        .and()
            .formLogin().usernameParameter("username1").passwordParameter("password1")// name at login view must username1 + password1
            .loginPage("/login1")// controller
            .loginProcessingUrl("/login_actionview_processing")// action in view of controller login1
            .successHandler(new AuthenticationSuccessHandler() {
                @Override
                public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) throws IOException, ServletException {
                	Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                	if (auth != null && auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
                		redirectStrategy.sendRedirect(request, response, "/admin/contact");
                	}else if (auth != null && auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER"))) {
                		redirectStrategy.sendRedirect(request, response, "/normal/contact");
                	}
                    
                }
            })
            //.defaultSuccessUrl("/home")// login thanh cong se chuyen vao day
            .failureUrl("/login1?error=true")// will send param(error) to controller /login1
            .permitAll()
        .and()
            .logout()
            .logoutUrl("/logout_app1")// if want logout -> run url: localhost:port/logout_app1
            .logoutSuccessUrl("/login1?logout=true") // will send param(logout) to controller /login1
            //.addLogoutHandler(logoutHandler)
            //.logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
            .invalidateHttpSession(true)
            .permitAll()
        .and()
            .csrf()
            .disable();
    }
}
