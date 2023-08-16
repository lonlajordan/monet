package com.gie.monet.models;

import com.gie.monet.utils.RoleListConverter;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String email;
    private String username;
    private String firstName;
    private String lastName;
    private boolean enabled;
    private LocalDateTime lastLogin;
    @Convert(converter = RoleListConverter.class)
    @Column(nullable = false, columnDefinition = "LONGTEXT")
    private List<Role> roles = new ArrayList<>();
}
