package com.g7.ercauthservice.model;

import com.g7.ercauthservice.entity.Role;
import lombok.*;

import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class UserRoleUpdateRequest {
    private String id;
    private Set<Role> roles;
}
