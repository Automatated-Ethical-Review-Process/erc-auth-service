package com.g7.ercauthservice.model;

import com.g7.ercauthservice.enums.NotificationType;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class NotificationCreateRequest {
    private String title;
    private String content;
    private String contentId;
    private String contentName;
    private NotificationType type;
    private String sender;
    private String receiver;
}
