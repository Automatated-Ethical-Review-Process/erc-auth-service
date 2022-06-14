package com.g7.ercauthservice.service;

import com.g7.ercauthservice.entity.Token;
import com.g7.ercauthservice.enums.EnumIssueType;

public interface TokenStoreService {

    void deleteToken(String token);
    String getTokenByIdAndIssueFor(String id, EnumIssueType issueType) throws Exception;
    Token storeToken(Token token);
    Boolean exists(String token);
}
