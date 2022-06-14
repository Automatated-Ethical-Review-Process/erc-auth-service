package com.g7.ercauthservice.service;

import org.springframework.stereotype.Service;

@Service
public interface DefaultDataService {

    void insertRolesToDB();
    void insertUsersToDB();
}
