package com.demo.jwt_authentication.config;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    public void sendVerificationCode(String to, String code) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Email verification code");
        message.setText("Your verification code is: " + code + "\n\n" +
                "Enter this code in the app to verify your email. " +
                "The code expires in 15 minutes.");
        mailSender.send(message);
    }
}
