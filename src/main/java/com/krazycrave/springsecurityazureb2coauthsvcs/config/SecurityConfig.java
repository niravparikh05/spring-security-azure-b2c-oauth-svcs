package com.krazycrave.springsecurityazureb2coauthsvcs.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    ObjectMapper objectMapper;
    JwtTokenStore jwtTokenStore;

    public SecurityConfig(ObjectMapper objectMapper, JwtTokenStore jwtTokenStore) {
        this.objectMapper = objectMapper;
        this.jwtTokenStore = jwtTokenStore;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
     return http.csrf().disable().cors()
             .and()
                .authorizeExchange()
                .pathMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
                .anyExchange().authenticated()
             .and()
                .oauth2Login()
                .authenticationSuccessHandler( this::onAuthenticationSuccess )
             .and()
                .exceptionHandling()
                .authenticationEntryPoint( this::authenticationEntryPoint )
             .and()
                .build();
    }

    /*
     * This method is invoked after oauth authentication is successful.
     */
    private Mono<Void> onAuthenticationSuccess(WebFilterExchange filterExchange, Authentication authentication) {
        try {
            // generate our own token from oauth authentication object which already contains a token
            String token = this.jwtTokenStore.generateToken(authentication);
            ServerHttpResponse response = filterExchange.getExchange().getResponse();
            return response.writeWith(
                    Mono.just(response.bufferFactory().allocateBuffer().write(
                            objectMapper.writeValueAsBytes(Collections.singletonMap("accessToken", token))
                    ))
            );
        } catch (Exception e) {
            // handle exception in a better way !
            e.printStackTrace();
        }
        return null;
    }

    private Mono<Void> authenticationEntryPoint(ServerWebExchange webExchange, AuthenticationException authenticationException) {
        String result = String.format("{\"code\":\"%s\",\"message\": \"%s\"}", "401", authenticationException.getMessage());
        ServerHttpResponse response = webExchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.writeWith(Mono.just(response.bufferFactory().allocateBuffer().write(result.getBytes())));
    }
    /*
     * Prepare CORS Configuration
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedMethods( Collections.singletonList( "*" ) );
        //to handle cors from angular app, as it seems like a different origin due to port number
        //DO NOT CONFIGURE LIKE THIS IS PRODUCTION
        corsConfiguration.setAllowedOrigins( Collections.singletonList( "http://localhost:4200" ) );
        corsConfiguration.setAllowCredentials( true );
        corsConfiguration.setAllowedHeaders( Collections.singletonList( "*" ) );

        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        urlBasedCorsConfigurationSource.registerCorsConfiguration( "/**", corsConfiguration);

        return urlBasedCorsConfigurationSource;
    }
}
