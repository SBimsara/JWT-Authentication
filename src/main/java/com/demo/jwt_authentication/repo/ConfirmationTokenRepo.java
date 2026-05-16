package com.demo.jwt_authentication.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.demo.jwt_authentication.token.ConfirmationToken;

import java.util.Optional;

public interface ConfirmationTokenRepo extends JpaRepository<ConfirmationToken, Long>{

    Optional<ConfirmationToken> findByToken(String token);
}
