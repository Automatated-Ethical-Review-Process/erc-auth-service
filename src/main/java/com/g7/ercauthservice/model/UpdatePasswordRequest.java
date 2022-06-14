package com.g7.ercauthservice.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class UpdatePasswordRequest {
    String oldPassword;
    String newPassword;
}
