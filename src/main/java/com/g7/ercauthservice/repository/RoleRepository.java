package com.g7.ercauthservice.repository;

import com.g7.ercauthservice.enums.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository("RoleRepository")
public interface RoleRepository extends JpaRepository<com.g7.ercauthservice.entity.Role,Long> {

    Optional<com.g7.ercauthservice.entity.Role> findByName(Role role);

}
