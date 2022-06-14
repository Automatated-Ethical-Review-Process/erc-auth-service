package com.g7.ercauthservice.repository;

import com.g7.ercauthservice.entity.Role;
import com.g7.ercauthservice.enums.EnumRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository("RoleRepository")
public interface RoleRepository extends JpaRepository<Role,Long> {

    Optional<Role> findByName(EnumRole role);

}
