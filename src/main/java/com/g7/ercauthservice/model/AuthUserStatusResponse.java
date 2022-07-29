package com.g7.ercauthservice.model;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@ToString
@Getter
@Setter
public class AuthUserStatusResponse {
    private Boolean isVerified;
    private Boolean isLocked;
    private Boolean isEnable;
}
