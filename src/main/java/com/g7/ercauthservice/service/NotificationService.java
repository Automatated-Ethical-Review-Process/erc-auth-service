package com.g7.ercauthservice.service;

import com.g7.ercauthservice.model.NotificationCreateRequest;

import javax.servlet.http.HttpServletRequest;

public interface NotificationService {

    void sendNotification(NotificationCreateRequest request, HttpServletRequest httpServletRequest);
    void notificationCreateRequestUpdateRole(String sender,String receiver,HttpServletRequest request);
    void notificationCreateRequestUpdateEmail(String sender,String receiver,HttpServletRequest request,String oldEmail,String newEmail);
    void notificationCreateRequestVerify(String sender,String receiver,HttpServletRequest request);
    void notificationCreateRequestReject(String sender,String receiver,HttpServletRequest request);
}
