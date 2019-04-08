package com.security.springsecurityauthserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

@Configuration
@EnableWebSecurity
public class ResourceServerConfig extends WebSecurityConfigurerAdapter {
	
    @Autowired
    private UserDetailsService customUserDetailsService; 
    
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.requestMatchers()
                .antMatchers("/login", "/oauth/authorize")
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .permitAll();
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

       auth.userDetailsService(customUserDetailsService);
//    	auth.inMemoryAuthentication()
//  	  .withUser("john").password(passwordEncoder.encode("123")).roles("USER").and()
//  	  .withUser("admin").password(passwordEncoder.encode("nimda")).roles("ADMIN");
    }
    
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
