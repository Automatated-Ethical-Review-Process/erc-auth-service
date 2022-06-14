package com.g7.ercauthservice.service.impl;

import com.g7.ercauthservice.entity.AuthUser;
import com.g7.ercauthservice.repository.AuthUserRepository;
import com.g7.ercauthservice.service.impl.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private AuthUserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser user = userRepository.findByEmail(username)
                .orElseThrow(()->new UsernameNotFoundException("User not found with email :" + username));
        return UserDetailsImpl.build(user);
    }

    public UserDetails loadUserByUserid(String id) throws UsernameNotFoundException {
        AuthUser user = userRepository.findById(id)
                .orElseThrow(()-> new UsernameNotFoundException("User not found with user name :" + id));
        return UserDetailsImpl.build(user);
    }
}
