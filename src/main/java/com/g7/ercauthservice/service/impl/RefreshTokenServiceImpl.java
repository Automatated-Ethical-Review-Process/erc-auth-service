package com.g7.ercauthservice.service.impl;

import com.g7.ercauthservice.entity.AuthUser;
import com.g7.ercauthservice.entity.RefreshToken;
import com.g7.ercauthservice.exception.TokenRefreshException;
import com.g7.ercauthservice.service.RefreshTokenService;
import com.g7.ercauthservice.repository.AuthUserRepository;
import com.g7.ercauthservice.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {

    @Value("${jwtRefreshExpirationMs}")
    private Long refreshTokenDurationMs;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private AuthUserRepository authUserRepository;

    public Optional<RefreshToken> findByToken(String token){
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken  createRefreshToken(String userId,String jwt){

        RefreshToken refreshToken = new RefreshToken();

        if(refreshTokenRepository.findByAuthUser_Id(userId).isPresent()){
            refreshToken = refreshTokenRepository.findByAuthUser_Id(userId).get();
        }else{
            if(authUserRepository.findById(userId).isPresent()){
                String [] token={jwt.substring(0,99), String.valueOf(Instant.now().hashCode()),jwt.substring(100,227)};
                refreshToken.setAuthUser(authUserRepository.findById(userId).get());
                refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
                refreshToken.setToken(token[0]+token[1]+token[2]);
                return refreshTokenRepository.save(refreshToken);
            }
        }
        return refreshToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token){
        if(token.getExpiryDate().compareTo(Instant.now())<0){
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(),"Refresh token was expired. Please make a new signing request");
        }
        return token;
    }

    @Transactional
    public void deleteByUserId(String userId){
        if(authUserRepository.findById(userId).isPresent()){
            AuthUser authUser =authUserRepository.findById(userId).get();
            refreshTokenRepository.deleteByAuthUser(authUser);
        }

    }
}
