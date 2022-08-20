package com.g7.ercauthservice.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class UpdateRoleRequest {
    private String id;
    private Set<String> roles ;
}
