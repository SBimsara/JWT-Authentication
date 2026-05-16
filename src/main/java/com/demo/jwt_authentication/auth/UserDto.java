package com.demo.jwt_authentication.auth;

import com.demo.jwt_authentication.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private Role role;
    private Boolean emailVerified;
    private String roleRequestStatus;
    private List<String> permissions;
}
