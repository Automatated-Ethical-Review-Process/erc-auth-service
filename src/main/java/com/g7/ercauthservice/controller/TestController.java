package com.g7.ercauthservice.controller;

import com.g7.ercauthservice.model.UserInfo;
import com.g7.ercauthservice.service.DefaultDataService;
import com.g7.ercauthservice.service.impl.DefaultDataServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/test")
public class TestController{

    @GetMapping("/user")
    public ResponseEntity<?> getMessage(@RequestBody UserInfo userInfo){
        //defaultDataService.sendUser(userInfo);
        return new ResponseEntity<>(userInfo,HttpStatus.OK);
    }
}
