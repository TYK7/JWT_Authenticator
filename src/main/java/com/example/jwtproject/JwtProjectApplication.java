package com.example.jwtproject;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing // For createdAt and updatedAt fields
@OpenAPIDefinition(
    info = @Info(title = "JWT Authentication API", version = "1.0", description = "API documentation for Spring Boot JWT Authentication Project"),
    servers = {
        @Server(url = "http://localhost:8080", description = "Local Development Server")
    }
)
public class JwtProjectApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtProjectApplication.class, args);
    }

}
