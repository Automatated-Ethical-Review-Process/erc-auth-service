package com.g7.ercauthservice.service.impl;

import com.g7.ercauthservice.enums.NotificationType;
import com.g7.ercauthservice.model.NotificationCreateRequest;
import com.g7.ercauthservice.model.UserInfo;
import com.g7.ercauthservice.service.NotificationService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;

@Service
public class NotificationServiceImpl implements NotificationService {

    @Value("${notification.api.add}")
    private String notificationCreateURI;

    @Override
    public void sendNotification(NotificationCreateRequest request, HttpServletRequest httpServletRequest) {
        String headerAuth = httpServletRequest.getHeader("Authorization");
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers =  new HttpHeaders();
        headers.add("Authorization",headerAuth);
        HttpEntity<NotificationCreateRequest> dataRequest = new HttpEntity<>(request,headers);
        System.out.println(dataRequest);
        ResponseEntity<?> dataResponse = restTemplate.exchange(notificationCreateURI, HttpMethod.POST,dataRequest,String.class);
        System.out.println(dataResponse);
    }

    @Override
    public void notificationCreateRequestUpdateRole(String sender,String receiver,HttpServletRequest request){
        String title ="Your user roles were changed";
        String content = "Your user roles were changed by Admin" +
                "Click hear to see changes";
        NotificationCreateRequest notificationCreateRequest= NotificationCreateRequest.builder()
                .title(title)
                .content(content)
                .contentId(null)
                .contentName(null)
                .sender(sender)
                .receiver(receiver)
                .type(NotificationType.USER_PROFILE)
                .build();
        sendNotification(notificationCreateRequest,request);
    }

    @Override
    public void notificationCreateRequestUpdateEmail(String sender,String receiver,HttpServletRequest request,String oldEmail,String newEmail){
        String title ="Your email changed to "+newEmail;
        String content = "Your email changed to "+newEmail+" from "+ oldEmail+".";
        NotificationCreateRequest notificationCreateRequest= NotificationCreateRequest.builder()
                .title(title)
                .content(content)
                .contentId(null)
                .contentName(null)
                .sender(sender)
                .receiver(receiver)
                .type(NotificationType.USER_PROFILE)
                .build();
        sendNotification(notificationCreateRequest,request);
    }

    @Override
    public void notificationCreateRequestVerify(String sender,String receiver,HttpServletRequest request){
        String title ="Your account verified";
        String content = "Your account verified. Now you are eligible to use all available functionalities.";
        NotificationCreateRequest notificationCreateRequest= NotificationCreateRequest.builder()
                .title(title)
                .content(content)
                .contentId(null)
                .contentName(null)
                .sender(sender)
                .receiver(receiver)
                .type(NotificationType.USER_PROFILE)
                .build();
        sendNotification(notificationCreateRequest,request);
    }

    @Override
    public void notificationCreateRequestReject(String sender, String receiver, HttpServletRequest request) {
        String title ="Your new user request is rejected  ";
        String content = "Your new user request is rejected . Now you are not eligible to use all available functionalities.";
        NotificationCreateRequest notificationCreateRequest= NotificationCreateRequest.builder()
                .title(title)
                .content(content)
                .contentId(null)
                .contentName(null)
                .sender(sender)
                .receiver(receiver)
                .type(NotificationType.USER_PROFILE)
                .build();
        sendNotification(notificationCreateRequest,request);
    }

}
