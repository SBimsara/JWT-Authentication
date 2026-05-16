package com.demo.jwt_authentication.service;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import com.demo.jwt_authentication.repo.ConfirmationTokenRepo;
import com.demo.jwt_authentication.token.ConfirmationToken;

@Service
@AllArgsConstructor
public class ConfirmationTokenService {

    private final ConfirmationTokenRepo confirmationTokenRepo;

    public void saveConfirmationToken(ConfirmationToken token){
        confirmationTokenRepo.save(token);
    }
}
