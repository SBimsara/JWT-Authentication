package com.demo.jwt_authentication;

import com.demo.jwt_authentication.auth.AuthenticationService;
import com.demo.jwt_authentication.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.demo.jwt_authentication.user.Role.ADMIN;
import static com.demo.jwt_authentication.user.Role.MANAGER;

@SpringBootApplication
public class JwtAuthenticationApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthenticationApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService service
	) {
		return args -> {
			var admin = RegisterRequest.builder()
					.firstname("admin")
					.lastname("admin")
					.email("admin@gmail.com")
					.password("admin")
					.role(ADMIN)
					.build();
			System.out.println("Admin token: " + service.register(admin).getToken());

			var manager = RegisterRequest.builder()
					.firstname("manager")
					.lastname("manager")
					.email("manager@gmail.com")
					.password("manager")
					.role(MANAGER)
					.build();
			System.out.println("Manager token: " + service.register(manager).getToken());
		};
	}
}

