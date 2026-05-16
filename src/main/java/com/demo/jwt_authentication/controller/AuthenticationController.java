package com.demo.jwt_authentication.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.demo.jwt_authentication.dto.AuthenticationRequest;
import com.demo.jwt_authentication.dto.AuthenticationResponse;
import com.demo.jwt_authentication.dto.RegisterRequest;
import com.demo.jwt_authentication.dto.ResendVerificationRequest;
import com.demo.jwt_authentication.dto.UserDTO;
import com.demo.jwt_authentication.dto.VerifyEmailRequest;
import com.demo.jwt_authentication.service.AuthenticationService;

import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    // end-point to register a new user and send OTP
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ){
        return ResponseEntity.ok(authenticationService.register(request));
    }

    // end-point to authenticate a user
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ){
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/verify-email")
    public ResponseEntity<AuthenticationResponse> verifyEmail(
            @RequestBody VerifyEmailRequest request
    ){
        return ResponseEntity.ok(authenticationService.verifyEmail(request));
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<AuthenticationResponse> resendVerification(
            @RequestBody ResendVerificationRequest request
    ){
        return ResponseEntity.ok(authenticationService.resendVerification(request));
    }

    // end-point to generate a new access token
    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        authenticationService.refreshToken(request, response);
    }

    @GetMapping("/me")
    public ResponseEntity<UserDTO> getCurrentUser(Authentication authentication) {
        if (authentication == null || authentication.getName() == null) {
            return ResponseEntity.status(401).build();
        }
        var userDto = authenticationService.getCurrentUser(authentication.getName());
        return ResponseEntity.ok(userDto);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        authenticationService.logout(request);
        return ResponseEntity.ok().build();
    }
}
