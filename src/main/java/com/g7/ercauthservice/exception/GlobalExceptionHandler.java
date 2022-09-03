package com.g7.ercauthservice.exception;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.persistence.EntityNotFoundException;
import javax.validation.ConstraintViolationException;
import java.net.ConnectException;
import java.util.ArrayList;
import java.util.List;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler{

    @ExceptionHandler(EntityNotFoundException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ApiError EntityNotFoundExceptionHandler(EntityNotFoundException ex){
        ApiError apiError = new ApiError();
            apiError.setFields(null);
            apiError.setMessage(ex.getMessage());
        return apiError;
    }

    @ExceptionHandler(AuthenticationException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ApiError AuthenticationExceptionHandler(AuthenticationException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage(ex.getMessage());
        return apiError;
    }

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ApiError AccessDeniedExceptionHandler(AccessDeniedException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage(ex.getMessage());
        return apiError;
    }

    @ExceptionHandler(EmailEqualException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError EmailEqualExceptionHandler(EmailEqualException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage(ex.getMessage());
        return apiError;
    }

    @ExceptionHandler(PasswordMatchingException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError PasswordMatchingExceptionHandler(PasswordMatchingException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage(ex.getMessage());
        return apiError;
    }

    @ExceptionHandler(RoleException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError RoleExceptionHandler(RoleException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage(ex.getMessage());
        return apiError;
    }

    @ExceptionHandler(UserAlreadyExistException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError UserAlreadyExistExceptionHandler(UserAlreadyExistException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage(ex.getMessage());
        return apiError;
    }

    @ExceptionHandler(HttpClientErrorException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError HttpClientErrorExceptionHandler(HttpClientErrorException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage("Rest Template error : "+ex.getMessage());
        return apiError;
    }

    @ExceptionHandler(ConnectException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError ConnectExceptionHandler(ConnectException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage(ex.getMessage());
        return apiError;
    }

    @ExceptionHandler(ResourceAccessException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError ResourceAccessExceptionHandler(ResourceAccessException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage("Resource access denied");
        return apiError;
    }

    @ExceptionHandler(CustomException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError CustomExceptionHandler(CustomException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage(ex.getMessage());
        return apiError;
    }

    @ExceptionHandler(Exception.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError AllExceptionHandler(Exception ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        System.out.println("hello");
        apiError.setMessage(ex.getMessage());
        return apiError;
    }
    //==========================jwt start=====================================

    @ExceptionHandler(MalformedJwtException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError MalformedJwtExceptionHandler(MalformedJwtException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage("Invalid JWT token ");
        return apiError;
    }

    @ExceptionHandler(SignatureException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError SignatureExceptionHandler(SignatureException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage("Invalid JWT Signature");
        return apiError;
    }

    @ExceptionHandler(ExpiredJwtException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError ExpiredJwtExceptionHandler(ExpiredJwtException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage("Token expired");
        return apiError;
    }

    @ExceptionHandler(UnsupportedJwtException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError UnsupportedJwtExceptionHandler(UnsupportedJwtException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage("Unsupported Token");
        return apiError;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseBody
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiError IllegalArgumentExceptionHandler(IllegalArgumentException ex){
        ApiError apiError = new ApiError();
        apiError.setFields(null);
        apiError.setMessage("Illegal arguments for token");
        return apiError;
    }
//=====================================jwt end========================================


    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        ApiError apiError = new ApiError();
        BindingResult result = ex.getBindingResult();
        List<FieldError> fieldErrors = result.getFieldErrors();
        List<String> fields = new ArrayList<>();
        for(FieldError fieldError:fieldErrors){
            if(!fields.contains(fieldError.getField())){
                fields.add(fieldError.getField());
            };
        }
        apiError.setFields(fields);
        apiError.setMessage("Invalid input");

        return new ResponseEntity<>(apiError,HttpStatus.BAD_REQUEST);
    }

    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        ApiError apiError = new ApiError();
        apiError.setMessage(ex.getMessage());
        apiError.setFields(null);
        return new ResponseEntity<>(apiError,HttpStatus.METHOD_NOT_ALLOWED);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        ApiError apiError = new ApiError();
        apiError.setMessage("Required request body is missing");
        apiError.setFields(null);
        return new ResponseEntity<>(apiError,HttpStatus.BAD_REQUEST);
    }
}
