package com.g7.ercauthservice.service;

import com.g7.ercauthservice.entity.Token;
import com.g7.ercauthservice.enums.EnumIssueType;

public interface TokenStoreService {

    void deleteToken(String token);
    Token getTokenByIdAndIssueFor(String id, EnumIssueType issueType) throws Exception;
    Token getTokenByIdAndIssueFor(String id) throws Exception;
    Token storeToken(Token token);
    Boolean exists(String token);
}
