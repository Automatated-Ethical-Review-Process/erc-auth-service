package com.g7.ercauthservice.repository;

import com.g7.ercauthservice.entity.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository("AuthUserRepository")
public interface AuthUserRepository extends JpaRepository<AuthUser,String> {

    Optional<AuthUser> findByEmail(String email);
    Boolean existsByEmail(String email);
    List<AuthUser> findAuthUserByIsVerified(Boolean isVerified);
    @Query(value = "SELECT exists (SELECT role_id FROM public.user_roles WHERE role_id=:id limit 1)",nativeQuery = true)
    Boolean checkRoleUnique(@Param("id") Integer id);

    @Query(value = "SELECT id, created_date, email, is_enable, is_locked, is_verified, modified_date, password, user_message\n" +
            "\tFROM public.users WHERE id IN (SELECT user_id FROM public.user_roles WHERE role_id=3) limit 1",nativeQuery = true)
    AuthUser getAuthUserByRole(@Param("id") Integer id);
}
