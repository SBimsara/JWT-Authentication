package com.demo.jwt_authentication.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.demo.jwt_authentication.entity.EmailVerificationToken;
import com.demo.jwt_authentication.entity.User;

import java.util.Optional;

public interface EmailVerificationTokenRepo extends JpaRepository<EmailVerificationToken, Integer> {
    Optional<EmailVerificationToken> findByToken(String token);
    void deleteAllByUser(User user);
}
