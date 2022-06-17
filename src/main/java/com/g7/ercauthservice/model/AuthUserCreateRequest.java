package com.g7.ercauthservice.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.util.Set;

@Data
@NoArgsConstructor
public class AuthUserCreateRequest {
    @NotBlank
    private String password;
}
