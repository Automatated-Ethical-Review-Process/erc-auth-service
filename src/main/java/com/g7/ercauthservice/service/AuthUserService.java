package com.g7.ercauthservice.service;

import com.g7.ercauthservice.entity.AuthUser;
import com.g7.ercauthservice.entity.Token;
import com.g7.ercauthservice.model.AuthUserCreateRequest;
import com.g7.ercauthservice.model.ForgotPasswordRequest;
import com.g7.ercauthservice.model.UpdateEmailRequest;

import java.util.Set;

public interface AuthUserService {

    AuthUser add(AuthUserCreateRequest request, Token token);
    void remove(String id);
    void updatePassword(String id,String oldPassword,String newPassword) throws Exception;
    void updateEmail(UpdateEmailRequest request) throws Exception;
    void updateRoles(Set<String> roles,String id) throws Exception;
    AuthUser getById(String id);
    Boolean existAuthUser(String Email);
    AuthUser getAuthUserByEmail(String email);
    void forgotPassword(String email, ForgotPasswordRequest request);

}
