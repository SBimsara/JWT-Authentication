package com.demo.jwt_authentication.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

import com.demo.jwt_authentication.entity.Role;

@Data
@Builder
@AllArgsConstructor
public class UserDTO {
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private Role role;
    private Boolean emailVerified;
    private String roleRequestStatus;
    private List<String> permissions;
}
