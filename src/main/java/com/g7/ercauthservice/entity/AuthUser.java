package com.g7.ercauthservice.entity;

import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Data
@NoArgsConstructor
@Entity
@Table(name = "users",uniqueConstraints = {
        @UniqueConstraint(columnNames = "email")
})
public class AuthUser {

    @Id
    @Column(name = "id",updatable = false)
    private String id = UUID.randomUUID()+""+ Instant.now().hashCode();

    @NotBlank
    @Size(max=50)
    @Email
    @Column(name = "email",nullable = false)
    private String email;

    @NotBlank
    @Column(name = "password",nullable = false)
    private String password;

    @Column(name = "is_verified",nullable = false)
    private Boolean isVerified;

    @Column(name = "is_locked",nullable = false)
    private Boolean isLocked;

    @Column(name = "is_enable",nullable = false)
    private Boolean isEnable;

    @Column(name = "created_date",nullable = false)
    private Instant createdDate=Instant.now();

    @Column(name = "modified_date",nullable = false)
    private Instant modifiedDate=Instant.now();

    @Column(name = "user_message")
    private String userMessage;

    @ManyToMany(fetch = FetchType.EAGER )
    @JoinTable(name = "user_roles",joinColumns = @JoinColumn(name ="user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles =  new HashSet<>();

    @Override
    public String toString() {
        return "AuthUser{" +
                "id='" + id + '\'' +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", isVerified=" + isVerified +
                ", isLocked=" + isLocked +
                ", createdDate=" + createdDate +
                ", modifiedDate=" + modifiedDate +
                ", roles=" + roles +
                '}';
    }
}
