package com.g7.ercauthservice.model;

import lombok.*;

import java.time.Instant;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class AuthUserResponse {
    private String id ;
    private Boolean isVerified;
    private Boolean isLocked;
    private Boolean isEnable;
    private Instant createdDate;
    private Instant modifiedDate;
    private Boolean hasReviewed;
}
