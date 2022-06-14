package com.g7.ercauthservice.repository;

import com.g7.ercauthservice.entity.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository("AuthUserRepository")
public interface AuthUserRepository extends JpaRepository<AuthUser,String> {

    Optional<AuthUser> findByEmail(String email);
    Boolean existsByEmail(String email);
}
