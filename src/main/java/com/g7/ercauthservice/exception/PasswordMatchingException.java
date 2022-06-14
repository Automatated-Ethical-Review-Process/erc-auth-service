package com.g7.ercauthservice.exception;

public class PasswordMatchingException extends RuntimeException {
    public PasswordMatchingException(String message) {
        super(message);
    }
}
