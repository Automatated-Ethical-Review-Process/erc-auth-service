package com.g7.ercauthservice.service.impl;

import com.g7.ercauthservice.entity.AuthUser;
import com.g7.ercauthservice.enums.Role;
import com.g7.ercauthservice.repository.AuthUserRepository;
import com.g7.ercauthservice.repository.RoleRepository;
import com.g7.ercauthservice.service.DefaultDataService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.transaction.Transactional;
import java.util.HashSet;
import java.util.Set;

@Component
@Slf4j
@Transactional
public class DefaultDataServiceImpl implements DefaultDataService {

    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private AuthUserRepository userRepository;
    @Autowired
    private AuthUserServiceImpl authUserService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostConstruct
    public void testMethod(){
        AuthUser authUser =authUserService.getAuthUserByRole(Role.ROLE_ADMIN);
        System.out.println(authUser);
    }

    @Override
    @PostConstruct
    public void insertRolesToDB() {
        if(roleRepository.findAll().isEmpty() && roleRepository.count() !=6){
            com.g7.ercauthservice.entity.Role role1 = new com.g7.ercauthservice.entity.Role(Role.ROLE_APPLICANT);
            com.g7.ercauthservice.entity.Role role2 = new com.g7.ercauthservice.entity.Role(Role.ROLE_INTERNAL_REVIEWER);
            com.g7.ercauthservice.entity.Role role3 = new com.g7.ercauthservice.entity.Role(Role.ROLE_EXTERNAL_REVIEWER);
            com.g7.ercauthservice.entity.Role role4 = new com.g7.ercauthservice.entity.Role(Role.ROLE_CLERK);
            com.g7.ercauthservice.entity.Role role5 = new com.g7.ercauthservice.entity.Role(Role.ROLE_SECRETARY);
            com.g7.ercauthservice.entity.Role role6 = new com.g7.ercauthservice.entity.Role(Role.ROLE_ADMIN);
            roleRepository.save(role1);
            roleRepository.save(role2);
            roleRepository.save(role3);
            roleRepository.save(role4);
            roleRepository.save(role5);
            roleRepository.save(role6);
            log.info("Inserted user roles to database");
            insertUsersToDB();
        }else {
            log.info("user roles already exists");
        }
    }

    @Override
    public void insertUsersToDB() {
        try{
            if(userRepository.findAll().isEmpty()){
                AuthUser authUser = new AuthUser();
                Set<String> roles = new HashSet<>();
                roles.add("admin");
                authUser.setEmail("admin@gmail.com");
                authUser.setPassword(passwordEncoder.encode("12345678"));
                authUser.setIsLocked(true);
                authUser.setIsVerified(true);
                authUser.setIsEnable(true);
                authUser.setRoles(authUserService.getRoles(roles));
                System.out.println(authUser);
                userRepository.save(authUser);

                log.info("successfully inserted user with all privileges admin@gmail.com PS 12345678");
            }else{
                log.info("Already created admin@gmail.com PS 12345678");
            }
        }catch (Exception e){
            log.info("Error insertion admin@gmail.com");
            throw e;
        }
    }


}
