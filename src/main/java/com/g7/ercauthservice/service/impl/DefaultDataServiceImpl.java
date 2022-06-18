package com.g7.ercauthservice.service.impl;

import com.g7.ercauthservice.entity.AuthUser;
import com.g7.ercauthservice.entity.Role;
import com.g7.ercauthservice.enums.EnumRole;
import com.g7.ercauthservice.model.AuthUserCreateRequest;
import com.g7.ercauthservice.repository.AuthUserRepository;
import com.g7.ercauthservice.repository.RoleRepository;
import com.g7.ercauthservice.service.DefaultDataService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.transaction.Transactional;
import java.util.HashSet;
import java.util.Set;

@Service
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

    @Override
    @PostConstruct
    public void insertRolesToDB() {
        if(roleRepository.findAll().isEmpty() && roleRepository.count() !=6){
            Role role1 = new Role(EnumRole.ROLE_APPLICANT);
            Role role2 = new Role(EnumRole.ROLE_INTERNAL_REVIEWER);
            Role role3 = new Role(EnumRole.ROLE_EXTERNAL_REVIEWER);
            Role role4 = new Role(EnumRole.ROLE_CLERK);
            Role role5 = new Role(EnumRole.ROLE_SECRETARY);
            Role role6 = new Role(EnumRole.ROLE_ADMIN);
            roleRepository.save(role1);
            roleRepository.save(role2);
            roleRepository.save(role3);
            roleRepository.save(role4);
            roleRepository.save(role5);
            roleRepository.save(role6);
            log.info("Inserted user roles to database");
        }else {
            log.info("user roles already exists");
        }
    }

    @Override
    @PostConstruct
    public void insertUsersToDB() {
        try{
            if(userRepository.findAll().isEmpty()){
                AuthUser authUser = new AuthUser();
                Set<String> roles = new HashSet<>();
                roles.add("admin");
                roles.add("secretary");
                roles.add("applicant");
                roles.add("clerk");
                roles.add("internal_reviewer");
                roles.add("external_reviewer");

                authUser.setEmail("admin@gmail.com");
                authUser.setPassword(passwordEncoder.encode("12345678"));
                authUser.setIsLocked(true);
                authUser.setIsVerified(true);
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
