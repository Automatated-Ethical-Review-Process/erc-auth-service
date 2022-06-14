package com.g7.ercauthservice.config;

import com.g7.ercauthservice.jwt.AuthEntrypointJwt;
import com.g7.ercauthservice.jwt.AuthTokenFilter;
import com.g7.ercauthservice.service.impl.UserDetailsServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Slf4j
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private AuthEntrypointJwt authEntrypointJwt;

    @Bean
    public AuthTokenFilter authTokenFilter(){
        return new AuthTokenFilter();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
                .exceptionHandling().authenticationEntryPoint(authEntrypointJwt).and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeHttpRequests()
                .antMatchers(HttpMethod.PATCH,"/**").denyAll()
                .antMatchers(HttpMethod.HEAD,"/**").denyAll()
                .antMatchers("/api/auth/test/**").permitAll()
                .antMatchers(HttpMethod.POST,"/api/auth/token/generate").permitAll()
                .antMatchers(HttpMethod.POST,"/api/auth/token/refresh").permitAll()
                .antMatchers(HttpMethod.POST,"/api/auth/create-user").permitAll()
                .antMatchers(HttpMethod.POST,"/api/auth/create-user/token").permitAll()
                .antMatchers(HttpMethod.POST,"/api/auth/create-user/invite/reviewer/token").permitAll()
                .antMatchers(HttpMethod.POST,"/api/auth/update/password/forgot/token").permitAll()
                .antMatchers(HttpMethod.POST,"/api/auth/update/password/forgot").permitAll()
                .antMatchers(HttpMethod.POST,"/api/auth/update/email").permitAll()
                .antMatchers(HttpMethod.POST,"/api/auth/request/validate").permitAll()
                .antMatchers(HttpMethod.POST,"/api/auth/current-user").authenticated()
                .antMatchers(HttpMethod.POST,"/api/auth/update/email/send/token").authenticated()
                .antMatchers(HttpMethod.POST,"/api/auth/update/password").authenticated()
                .antMatchers(HttpMethod.POST,"/api/auth/update/roles").authenticated()
                .antMatchers(HttpMethod.POST,"/api/auth/token/validate").authenticated()
                .antMatchers("/**").denyAll();

        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}
