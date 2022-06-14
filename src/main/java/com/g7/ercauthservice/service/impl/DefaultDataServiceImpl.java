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
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.HashSet;
import java.util.Set;

@Service
@Slf4j
public class DefaultDataServiceImpl implements DefaultDataService {

    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private AuthUserRepository userRepository;
    @Autowired
    private AuthUserServiceImpl authUserService;

    @Override
    @PostConstruct
    public void insertRolesToDB() {
        if(roleRepository.findAll().isEmpty() && roleRepository.count() !=5){
            Role role1 = new Role(EnumRole.ROLE_APPLICANT);
            Role role2 = new Role(EnumRole.ROLE_REVIEWER);
            Role role3 = new Role(EnumRole.ROLE_CLERK);
            Role role4 = new Role(EnumRole.ROLE_SECRETARY);
            Role role5 = new Role(EnumRole.ROLE_ADMIN);
            roleRepository.save(role1);
            roleRepository.save(role2);
            roleRepository.save(role3);
            roleRepository.save(role4);
            roleRepository.save(role5);
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
                AuthUserCreateRequest request = new AuthUserCreateRequest();
                Set<String> roles = new HashSet<>();
                roles.add("admin");
                roles.add("secretary");
                roles.add("applicant");
                roles.add("clerk");
                roles.add("reviewer");

                request.setEmail("admin@gmail.com");
                request.setPassword("12345678");
                request.setRoles(roles);
                AuthUser user = authUserService.add(request);
                if(user.getRoles().isEmpty()){
                    authUserService.remove(user.getId());
                }
                log.info("successfully inserted user with all privileges admin@gmail.com PS 12345678");
            }
        }catch (Exception e){
            log.info("Error insertion admin@gmail.com");
            throw e;
        }
    }
}
