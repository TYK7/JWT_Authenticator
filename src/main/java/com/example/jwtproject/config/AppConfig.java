package com.example.jwtproject.config;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class AppConfig {

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        // Customize RestTemplate if needed (e.g., timeouts, interceptors)
        return builder.build();
    }

    @Bean
    public WebClient.Builder webClientBuilder() {
        // Customize WebClient.Builder if needed (e.g., default headers, timeouts)
        return WebClient.builder();
    }
}
