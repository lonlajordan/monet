package com.gie.monet.models;

import lombok.Getter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Getter
@Entity
public class Bank {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    @OneToMany(mappedBy = "bank", orphanRemoval = true)
    private List<Agency> agencies = new ArrayList<>();
    @OneToMany(mappedBy = "bank", orphanRemoval = true)
    private List<Product> products = new ArrayList<>();
}
