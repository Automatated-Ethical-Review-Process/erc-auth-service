package com.g7.ercauthservice.exception;

public class EmailEqualException extends RuntimeException{
    private static final long serialVersionUID = 1L;

    public EmailEqualException(String message) {
        super(message);
    }
}
