package com.g7.ercauthservice.model;

import lombok.AllArgsConstructor;
import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

@Data
@AllArgsConstructor
public class AuthUserSignInRequest {
    @Email
    private String email;
    @NotEmpty
    private String password;
}
