package com.g7.ercauthservice.entity;

import com.g7.ercauthservice.enums.EnumIssueType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "token")
@AllArgsConstructor
@NoArgsConstructor
@Data
public class Token {

    @Id
    private String id = UUID.randomUUID().toString();
    @Column(columnDefinition = "TEXT")
    private String token;
    @Enumerated(EnumType.STRING)
    @Column(length = 40)
    private EnumIssueType issueFor;
    @Column(name = "uid")
    private String userId;

    public Token(String token, EnumIssueType issueFor, String userId) {
        this.token = token;
        this.issueFor = issueFor;
        this.userId = userId;
    }
}
