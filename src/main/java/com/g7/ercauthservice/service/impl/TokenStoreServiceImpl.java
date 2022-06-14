package com.g7.ercauthservice.service.impl;

import com.g7.ercauthservice.entity.Token;
import com.g7.ercauthservice.enums.EnumIssueType;
import com.g7.ercauthservice.repository.TokenRepository;
import com.g7.ercauthservice.service.TokenStoreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TokenStoreServiceImpl implements TokenStoreService {

    @Autowired
    private TokenRepository tokenRepository;
    @Override
    public void deleteToken(String token) {
        try {
            Token token1 = tokenRepository.findTokenByToken(token).get();
            tokenRepository.delete(token1);
        }catch (Exception e){
            throw e;
        }
    }

    @Override
    public Token getTokenByIdAndIssueFor(String id, EnumIssueType issueType) throws Exception {
        try {
            Token token = tokenRepository.findById(id).get();
            if(!exists(id) || token.getIssueFor() != issueType){
                throw  new Exception("Invalid token");
            }
            return token;
        } catch (Exception e) {
           throw e;
        }
    }

    public Token getTokenByIdAndIssueFor(String id) throws Exception {
        try {
            Token token = tokenRepository.findById(id).get();
            if(!exists(id)){
                throw  new Exception("Invalid token");
            }
            return token;
        } catch (Exception e) {
            throw e;
        }
    }

    @Override
    public Token storeToken(Token token) {
        return tokenRepository.save(token);
    }

    @Override
    public Boolean exists(String id) {
        return tokenRepository.existsById(id);
    }
}
