package com.demo.jwt_authentication.auth;

import com.demo.jwt_authentication.config.EmailService;
import com.demo.jwt_authentication.config.JwtService;
import com.demo.jwt_authentication.token.Token;
import com.demo.jwt_authentication.token.TokenRepo;
import com.demo.jwt_authentication.token.TokenType;
import com.demo.jwt_authentication.user.User;
import com.demo.jwt_authentication.user.UserRepo;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepo userRepo;
    private final TokenRepo tokenRepo;
    private final EmailVerificationTokenRepo verificationTokenRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;

    public AuthenticationResponse register(RegisterRequest request) {
        if (userRepo.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already in use");
        }

        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .emailVerified(false)
                .enabled(true)
                .locked(false)
                .build();

        var savedUser = userRepo.save(user);
        var verificationToken = createVerificationToken(savedUser);
        emailService.sendVerificationCode(savedUser.getEmail(), verificationToken.getToken());

        return AuthenticationResponse.builder()
                .verificationSent(true)
                .user(toUserDto(savedUser))
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var user = userRepo.findByEmail(request.getEmail()).orElseThrow();
        if (!Boolean.TRUE.equals(user.getEmailVerified())) {
            throw new IllegalStateException("Email address has not been verified");
        }

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);

        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepo.save(token);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .user(toUserDto(user))
                .build();
    }

    public AuthenticationResponse verifyEmail(VerifyEmailRequest request) {
        var user = userRepo.findByEmail(request.getEmail()).orElseThrow();
        if (Boolean.TRUE.equals(user.getEmailVerified())) {
            throw new IllegalStateException("Email already verified");
        }

        var verificationToken = verificationTokenRepo.findByToken(request.getOtp())
                .orElseThrow(() -> new IllegalArgumentException("Invalid verification code"));

        if (!verificationToken.getUser().getEmail().equalsIgnoreCase(user.getEmail())) {
            throw new IllegalArgumentException("Invalid verification code");
        }

        if (verificationToken.isUsed() || verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Verification code has expired");
        }

        verificationToken.setUsed(true);
        verificationTokenRepo.save(verificationToken);

        user.setEmailVerified(true);
        userRepo.save(user);

        return AuthenticationResponse.builder()
                .verificationSent(false)
                .user(toUserDto(user))
                .build();
    }

    public AuthenticationResponse resendVerification(ResendVerificationRequest request) {
        var user = userRepo.findByEmail(request.getEmail()).orElseThrow();
        if (Boolean.TRUE.equals(user.getEmailVerified())) {
            throw new IllegalStateException("Email already verified");
        }

        verificationTokenRepo.deleteAllByUser(user);
        var verificationToken = createVerificationToken(user);
        emailService.sendVerificationCode(user.getEmail(), verificationToken.getToken());

        return AuthenticationResponse.builder()
                .verificationSent(true)
                .user(toUserDto(user))
                .build();
    }

    private void revokeAllUserTokens(User user) {
        var validTokens = tokenRepo.findAllValidTokensByUserId(user.getId());

        if (validTokens.isEmpty()) {
            return;
        }

        validTokens.forEach(token -> {
            token.setRevoked(true);
            token.setExpired(true);
        });
        tokenRepo.saveAll(validTokens);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader("Authorization");
        final String refreshToken;
        final String email;

        if (authHeader == null || !authHeader.startsWith(("Bearer "))) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        refreshToken = authHeader.substring((7));
        email = jwtService.extractUsername(refreshToken);

        if (email == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        var user = this.userRepo.findByEmail(email).orElseThrow();

        if (jwtService.isTokenValid(refreshToken, user)) {
            var accessToken = jwtService.generateToken(user);

            revokeAllUserTokens(user);

            var token = Token.builder()
                    .user(user)
                    .token(accessToken)
                    .tokenType(TokenType.BEARER)
                    .expired(false)
                    .revoked(false)
                    .build();
            tokenRepo.save(token);

            var authResponse = AuthenticationResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .user(toUserDto(user))
                    .build();
            new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    public UserDto getCurrentUser(String email) {
        var user = userRepo.findByEmail(email).orElseThrow();
        return toUserDto(user);
    }

    public void logout(HttpServletRequest request) {
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        final String jwt = authHeader.substring(7);
        tokenRepo.findByToken(jwt).ifPresent(token -> {
            token.setRevoked(true);
            token.setExpired(true);
            tokenRepo.save(token);
        });
    }

    private EmailVerificationToken createVerificationToken(User user) {
        var otp = generateOtp();
        verificationTokenRepo.deleteAllByUser(user);
        var token = EmailVerificationToken.builder()
                .token(otp)
                .expiryDate(LocalDateTime.now().plusMinutes(15))
                .used(false)
                .user(user)
                .build();
        return verificationTokenRepo.save(token);
    }

    private String generateOtp() {
        int code = ThreadLocalRandom.current().nextInt(100000, 1000000);
        return String.valueOf(code);
    }

    private UserDto toUserDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .firstname(user.getFirstname())
                .lastname(user.getLastname())
                .email(user.getEmail())
                .role(user.getRole())
                .emailVerified(user.getEmailVerified())
                .roleRequestStatus(null)
                .permissions(user.getRole() == null ? List.of() : user.getRole().getPermissions().stream().map(permission -> permission.getPermission()).collect(Collectors.toList()))
                .build();
    }
}
