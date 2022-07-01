package com.g7.ercauthservice.service.impl;

import com.g7.ercauthservice.entity.AuthUser;
import com.g7.ercauthservice.entity.Token;
import com.g7.ercauthservice.enums.Role;
import com.g7.ercauthservice.exception.EmailEqualException;
import com.g7.ercauthservice.exception.PasswordMatchingException;
import com.g7.ercauthservice.exception.RoleException;
import com.g7.ercauthservice.model.AuthUserCreateRequest;
import com.g7.ercauthservice.model.ForgotPasswordRequest;
import com.g7.ercauthservice.model.UpdateEmailRequest;
import com.g7.ercauthservice.repository.AuthUserRepository;
import com.g7.ercauthservice.repository.RoleRepository;
import com.g7.ercauthservice.security.JwtUtils;
import com.g7.ercauthservice.service.AuthUserService;
import com.g7.ercauthservice.service.RefreshTokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@Slf4j
@Transactional
public class AuthUserServiceImpl implements AuthUserService {

    @Autowired
    private AuthUserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtils jwtUtils;
    @Override
    public AuthUser add(AuthUserCreateRequest request, Token token) {
        AuthUser authUser = new AuthUser();
        authUser.setEmail(jwtUtils.generateEmailFromToken(token.getToken()));
        authUser.setPassword(passwordEncoder.encode(request.getPassword()));
        authUser.setIsLocked(true);
        authUser.setIsVerified(true);
        Set<String> roles = new HashSet<>();
        switch (token.getIssueFor()){
            case FOR_INVITE_REVIEWER:
                roles.add("applicant");
                roles.add("external_reviewer");
                break;
            case FOR_INVITE_SECRETARY:
                roles.add("secretary");
                roles.add("reviewer");
                break;
            case FOR_INVITE_CLERK:
                roles.add("clerk");
                break;
            default:
                roles.add("applicant");
        }
        authUser.setRoles(getRoles(roles));
        System.out.println(authUser);
        return userRepository.save(authUser);
    }

    @Override
    public void remove(String id) {
        AuthUser authUser = userRepository.findById(id).get();
        refreshTokenService.deleteByUserId(authUser.getId());
        userRepository.delete(authUser);
    }

    @Override
    public void passwordCheck(String id, String password) {
        try {
            AuthUser authUser = userRepository.findById(id).get();
            if(!passwordEncoder.matches(password, authUser.getPassword())){
                throw new PasswordMatchingException("Password is wrong");
            }
        }catch (Exception e){
            throw e;
        }
    }
    @Override
    public void updatePassword(String id, String oldPassword, String newPassword) {
        try {
            AuthUser authUser = userRepository.findById(id).get();
            if(!passwordEncoder.matches(oldPassword, authUser.getPassword())){
                throw new PasswordMatchingException("Old password not match");
            }
            if(passwordEncoder.matches(newPassword, authUser.getPassword())){
                throw new PasswordMatchingException("Old password and new password are same");
            }
            authUser.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(authUser);
            refreshTokenService.deleteByUserId(authUser.getId());
        }catch (Exception e){
            throw e;
        }
    }

    @Override
    public void updateEmail(UpdateEmailRequest request) {
        String oldEmail = request.getOldEmail();
        String newEmail = request.getNewEmail();
        AuthUser authUser = userRepository.findById(request.getId()).get();
        try {
            if(oldEmail.equals(authUser.getEmail()) && oldEmail.equals(newEmail)){
                throw new EmailEqualException("Old email and new email are same");
            }
            if(existAuthUser(newEmail)){
                throw new EmailEqualException("Email already exists");
            }
            authUser.setEmail(newEmail);
            userRepository.save(authUser);
            refreshTokenService.deleteByUserId(authUser.getId());
        }catch (Exception e){
            throw e;
        }
    }
    @Override
    public void updateRoles(Set<String> roles,String id) {
        AuthUser authUser = userRepository.findById(id).get();
        if(1 <= getRoles(roles).size() && getRoles(roles).size()<5){
            Set<com.g7.ercauthservice.entity.Role> enumRoles = getRoles(roles);
            for (com.g7.ercauthservice.entity.Role role:enumRoles) {
                if(checkRoleUnique(role.getName()) && role.getName()== Role.ROLE_CLERK){
                    throw new RoleException("This is unique role CLERK");
                }else if(checkRoleUnique(role.getName()) && role.getName()== Role.ROLE_SECRETARY){
                    throw new RoleException("This is unique role SECRETARY");
                }else if(checkRoleUnique(role.getName()) && role.getName()== Role.ROLE_ADMIN){
                    throw new RoleException("This is unique role ADMIN");
                }
            }
            if(enumRoles.contains(null)){
                throw new RoleException("Your entered invalid role");
            }
            authUser.setRoles(enumRoles);
            userRepository.save(authUser);
        }else{
            throw new RoleException("Invalid roles as argument");
        }
    }

    @Override
    public AuthUser getById(String id) {
        return userRepository.findById(id).get();
    }

    @Override
    public Boolean existAuthUser(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public AuthUser getAuthUserByEmail(String email) {
        return userRepository.findByEmail(email).get();
    }

    @Override
    public void forgotPassword(String email, ForgotPasswordRequest request) {
        System.out.println(request.getPassword());
        if(!existAuthUser(email)){
            throw new EntityNotFoundException("User not found for given email");
        }
        AuthUser authUser = getAuthUserByEmail(email);
        if(passwordEncoder.matches(request.getPassword(), authUser.getPassword())){
            throw new PasswordMatchingException("You can't use old password again");
        }
        authUser.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(authUser);
    }


    public Set<com.g7.ercauthservice.entity.Role> getRoles(Set<String> strRoles){
        Set<com.g7.ercauthservice.entity.Role> roles = new HashSet<>();
        strRoles.forEach(role ->{
            switch (role){
                case "admin":
                    com.g7.ercauthservice.entity.Role superAdminRole = roleRepository.findByName(Role.ROLE_ADMIN)
                            .orElseThrow(()-> new RuntimeException("Error: Role is not found."));
                    roles.add(superAdminRole);
                    break;
                case "secretary":
                    com.g7.ercauthservice.entity.Role secretaryRole = roleRepository.findByName(Role.ROLE_SECRETARY)
                            .orElseThrow(()-> new RuntimeException("Error: Role is not found."));
                    roles.add(secretaryRole);
                    break;

                case "clerk":
                    com.g7.ercauthservice.entity.Role clerkRole = roleRepository.findByName(Role.ROLE_CLERK)
                            .orElseThrow(()-> new RuntimeException("Error: Role is not found."));
                    roles.add(clerkRole);
                    break;
                case "internal_reviewer":
                    com.g7.ercauthservice.entity.Role ireviewerRole = roleRepository.findByName(Role.ROLE_INTERNAL_REVIEWER)
                            .orElseThrow(()-> new RuntimeException("Error: Role is not found."));
                    roles.add(ireviewerRole);
                    break;
                case "external_reviewer":
                    com.g7.ercauthservice.entity.Role ereviewerRole = roleRepository.findByName(Role.ROLE_EXTERNAL_REVIEWER)
                            .orElseThrow(()-> new RuntimeException("Error: Role is not found."));
                    roles.add(ereviewerRole);
                    break;
                case "applicant":
                    com.g7.ercauthservice.entity.Role applicantRole = roleRepository.findByName(Role.ROLE_APPLICANT)
                            .orElseThrow(()-> new RuntimeException("Error: Role is not found."));
                    roles.add(applicantRole);
                    break;
                default:
                    roles.add(null);
                    break;
            }
        });
        return roles;
    }

    public Set<String> setRoles(List<String> strRoles){
        Set<String> roles = new HashSet<>();
        strRoles.forEach(role ->{
            switch (role){
                case "ROLE_ADMIN":
                    roles.add("admin");
                    break;
                case "ROLE_SECRETARY":
                    roles.add("secretary");
                    break;
                case "ROLE_CLERK":
                    roles.add("clerk");
                    break;
                case "ROLE_INTERNAL_REVIEWER":
                    roles.add("internal_reviewer");
                    break;
                case "ROLE_EXTERNAL_REVIEWER":
                    roles.add("external_reviewer");
                    break;
                case "ROLE_APPLICANT":
                    roles.add("applicant");
            }
        });
        return roles;
    }

    public Set<String> setRoles(Set<Role> strRoles){
        Set<String> roles = new HashSet<>();
        strRoles.forEach(role ->{
            switch (role){
                case ROLE_ADMIN:
                    roles.add("admin");
                    break;
                case ROLE_SECRETARY:
                    roles.add("secretary");
                    break;
                case ROLE_CLERK:
                    roles.add("clerk");
                    break;
                case ROLE_INTERNAL_REVIEWER:
                    roles.add("internal_reviewer");
                    break;
                case ROLE_EXTERNAL_REVIEWER:
                    roles.add("external_reviewer");
                    break;
                case ROLE_APPLICANT:
                    roles.add("applicant");
            }
        });
        return roles;
    }

    public Boolean checkRoleUnique(Role role){
        return userRepository.checkRoleUnique(roleRepository.findByName(role).get().getId());
    }
}
