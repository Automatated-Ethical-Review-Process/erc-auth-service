package com.g7.ercauthservice.model;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.*;
import java.net.URL;
import java.util.List;
import java.util.Set;

@Data
@NoArgsConstructor
public class AuthUserCreateRequest {
    @NotBlank
    private String password;
    @NotNull
    private String name;
    @Size(min = 4)
    @NotNull
    private String address;
    //@Pattern(regexp = "(^[0-9]{10}$)",message = "Invalid land number")
    @Size(max = 10)
    private String landNumber;
    @Pattern(regexp = "(^[0-9]{10}$)",message = "Invalid mobile number")
    @Size(max = 10)
    private String mobileNumber;
    @NotNull
    private Boolean isUnderGraduate;
    private String nic;
    private String passport;
    private String occupation;
    private String position;
    private String university;
    private String faculty;
    private String year;
    private String registrationNumber;
    private Set<String> educationalQualifications ;
}
