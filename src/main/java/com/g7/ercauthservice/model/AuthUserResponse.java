package com.g7.ercauthservice.model;

import lombok.AllArgsConstructor;

import java.util.Set;

@AllArgsConstructor
public class AuthUserResponse {
    private String access;
    private String refresh;
    private Set<String> roles;
}
