package com.g7.ercauthservice.security;

import com.g7.ercauthservice.exception.ApiError;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Slf4j
public class AuthEntrypointJwt implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        log.error("Unauthorized error: {}",authException.getMessage());
        response.setContentType("application/json");
        ApiError apiError = new ApiError();
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,apiError.toString());
    }
}
