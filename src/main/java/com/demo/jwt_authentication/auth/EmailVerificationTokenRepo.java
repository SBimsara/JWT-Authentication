package com.demo.jwt_authentication.auth;

import com.demo.jwt_authentication.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface EmailVerificationTokenRepo extends JpaRepository<EmailVerificationToken, Integer> {
    Optional<EmailVerificationToken> findByToken(String token);
    void deleteAllByUser(User user);
}
