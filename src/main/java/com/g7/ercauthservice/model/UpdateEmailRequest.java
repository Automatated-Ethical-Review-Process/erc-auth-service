package com.g7.ercauthservice.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class UpdateEmailRequest {
    private String id;
    private String oldEmail;
    private String newEmail;
}
