package com.demo.jwt_authentication.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.demo.jwt_authentication.entity.User;

import java.util.Optional;

public interface UserRepo extends JpaRepository<User, Integer>{
    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);
}
