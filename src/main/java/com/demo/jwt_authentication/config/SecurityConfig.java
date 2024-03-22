package com.demo.jwt_authentication.config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout;

import static com.demo.jwt_authentication.user.Permission.*;
import static com.demo.jwt_authentication.user.Role.ADMIN;
import static com.demo.jwt_authentication.user.Role.MANAGER;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
//        http
//                .csrf(Customizer.withDefaults())
//                .disable()
//                .authorizeHttpRequests(Customizer.withDefaults())
//                .requestMatchers("/api/v1/auth/**")
//                .permitAll()
//                .anyRequest()
//                .authenticated()
//                .and()
//                .sessionManagement(SessionCreationPolicy.STATELESS)
//                .and()
//                .authenticationProvider(authenticationProvider)
//                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/v1/auth/**").permitAll()

                        .requestMatchers("api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
                        .requestMatchers(HttpMethod.GET,"api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                        .requestMatchers(HttpMethod.POST,"api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                        .requestMatchers(HttpMethod.PUT,"api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                        .requestMatchers(HttpMethod.DELETE,"api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

                        .requestMatchers("api/v1/admin/**").hasRole(ADMIN.name())
                        .requestMatchers(HttpMethod.GET,"api/v1/admin/**").hasAuthority(ADMIN_READ.name())
                        .requestMatchers(HttpMethod.POST,"api/v1/admin/**").hasAuthority(ADMIN_CREATE.name())
                        .requestMatchers(HttpMethod.PUT,"api/v1/admin/**").hasAuthority(ADMIN_UPDATE.name())
                        .requestMatchers(HttpMethod.DELETE,"api/v1/admin/**").hasAuthority(ADMIN_DELETE.name())

                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
//                .logout(Customizer.withDefaults());
//                .logoutUrl("/api/v1/auth/logout")
//                .addLogoutHandler(null)
//                .logoutSuccessHandler((request, response, authentication) -> {
//                    SecurityContextHolder.clearContext();
//                });

                .logout(logout -> logout
                    .logoutUrl("/api/v1/auth/logout")
                    .logoutSuccessUrl(null)
                    .addLogoutHandler(logoutHandler)
                    .logoutSuccessHandler((request, response, authentication) -> {
                        SecurityContextHolder.clearContext();
                    })
                );

        return http.build();

    }
}
