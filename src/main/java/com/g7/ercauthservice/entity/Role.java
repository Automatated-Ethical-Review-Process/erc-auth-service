package com.g7.ercauthservice.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Entity
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Enumerated(EnumType.STRING)
    @Column(length = 25)
    private com.g7.ercauthservice.enums.Role name;

    public Role(com.g7.ercauthservice.enums.Role name) {
        this.name = name;
    }
}
