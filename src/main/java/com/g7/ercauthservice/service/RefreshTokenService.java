package com.g7.ercauthservice.service;

import com.g7.ercauthservice.entity.RefreshToken;

import java.util.Optional;

public interface RefreshTokenService {

    Optional<RefreshToken> findByToken(String token);
    RefreshToken  createRefreshToken(String userId,String jwt);
    RefreshToken verifyExpiration(RefreshToken token);
    void deleteByUserId(String userId);
}
