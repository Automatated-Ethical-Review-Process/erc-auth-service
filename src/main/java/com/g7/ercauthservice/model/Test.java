package com.g7.ercauthservice.model;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;

public class Test {

    @Pattern(regexp = "([A-Z])\\w+")
    @NotEmpty(message = "Can not be empty")
    private String name;
    @NotEmpty(message = "Can not be empty")
    private String telephone;
    @NotEmpty(message = "Can not be empty")
    private String address;
}
