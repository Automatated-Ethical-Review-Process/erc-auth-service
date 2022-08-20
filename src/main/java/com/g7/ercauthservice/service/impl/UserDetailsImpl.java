package com.g7.ercauthservice.service.impl;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.g7.ercauthservice.entity.AuthUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class UserDetailsImpl implements UserDetails {

    private final String id;
    private final String email;
    @JsonIgnore
    private final String password;
    private static Boolean isLocked;
    private static  Boolean isVerified;

    private static Boolean isEnable;

    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(String id, String email, String password, Boolean isLocked, Boolean isVerified,Boolean isEnable, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.email = email;
        this.password = password;
        UserDetailsImpl.isLocked = isLocked;
        UserDetailsImpl.isVerified = isVerified;
        UserDetailsImpl.isEnable = isEnable;
        this.authorities = authorities;
    }

    public static UserDetailsImpl build(AuthUser user){
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        return new UserDetailsImpl(
                user.getId(),
                user.getEmail(),
                user.getPassword(),
                user.getIsLocked(), user.getIsVerified(),user.getIsEnable(), authorities
        );
    }


    public String getId() {
        return id;
    }

    public Boolean getIsVerified(){
        return isVerified;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return isEnable;
    }
}
