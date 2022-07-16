package com.g7.ercauthservice.model;

import lombok.*;

import javax.validation.constraints.*;
import java.net.URL;
import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
@ToString
public class UserInfo {

    @NotNull
    private String id ;

    @NotBlank
    @Size(max=50)
    @Email(message = "Invalid Email")
    private String email;

    @NotNull
    private String name;

    @Size(min = 4)
    @NotNull
    private String address;

    @Pattern(regexp = "(^[0-9]{10}$)",message = "Invalid land number")
    @Size(max = 10)
    private String landNumber;

    @Pattern(regexp = "(^[0-9]{10}$)",message = "Invalid mobile number")
    @Size(max = 10)
    private String mobileNumber;

    @NotNull
    private Boolean isUnderGraduate;

    private String nic;

    private String passport;

    @NotNull
    private URL idImg;

    private String occupation;

    private String position;

    private String university;

    private String faculty;

    private String year;

    private String registrationNumber;

    private List<String> educationalQualifications ;
}
