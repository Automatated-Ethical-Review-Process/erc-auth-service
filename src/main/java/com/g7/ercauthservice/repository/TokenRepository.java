package com.g7.ercauthservice.repository;

import com.g7.ercauthservice.entity.Token;
import com.g7.ercauthservice.enums.EnumIssueType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository("TokenRepository")
public interface TokenRepository extends JpaRepository<Token,String> {

    Optional<Token> findTokenByUserIdAndToken (String userId, String token);
    Optional<Token> findTokenByToken(String token);
    Optional<Token> findTokenByIssueForAndToken(EnumIssueType issueFor, String token);
}
