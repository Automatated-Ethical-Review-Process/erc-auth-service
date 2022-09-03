package com.g7.ercauthservice.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.g7.ercauthservice.entity.AuthUser;
import com.g7.ercauthservice.entity.Role;
import com.g7.ercauthservice.entity.Token;
import com.g7.ercauthservice.model.*;
import net.minidev.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Set;

public interface AuthUserService {

    AuthUser add(String password, Token token);
    void remove(String id);
    void updatePassword(String id,String oldPassword,String newPassword) throws Exception;
    String updateEmail(UpdateEmailRequest request) throws Exception;
    AuthUser updateRoles(Set<String> roles,String id) throws Exception;
    AuthUser getById(String id);
    Boolean existAuthUser(String Email);
    AuthUser getAuthUserByEmail(String email);
    void forgotPassword(String email, ForgotPasswordRequest request);
    void passwordCheck(String id,String password);
    JSONObject generateToken(AuthUserSignInRequest request);
    void updateEmailRollBack(UpdateEmailRequest request);
    void changeEnableState(String id);
    void changeLockState(String id, HttpServletRequest httpServletRequest) throws JsonProcessingException;
    void changeVerifiedState(String id);
    void roleUpdateByUser(String uid, Set<Role> roles);
    AuthUserStatusResponse getUserStatesById(String id);
    List<AuthUserResponse> getAllAuthUser();
    List<AuthUserResponse> getAllUnVerifiedAuthUsers(boolean isVerified);
    void setUserMessage(String id,String message);
    AuthUser getAuthUserByRole(com.g7.ercauthservice.enums.Role role);

}
