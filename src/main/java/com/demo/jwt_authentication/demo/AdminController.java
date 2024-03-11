package com.demo.jwt_authentication.demo;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/admin")
@CrossOrigin(origins = "*")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')") //name of the permission is used
    public String get(){
        return "GET:: admin controller";
    }

    @PostMapping
    @PreAuthorize("hasAuthority('admin:create')")
    public String post(){
        return "POST:: admin controller";
    }

    @PutMapping
    @PreAuthorize("hasAuthority('admin:update')")
    public String put(){
        return "PUT:: admin controller";
    }

    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:delete')")
    public String delete(){
        return "DELETE:: admin controller";
    }
}

