package com.example.jwtproject.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import org.springframework.http.HttpMethod;

import java.util.Map;

@Data
public class ForwardRequest {

    @NotBlank(message = "Target URL cannot be blank")
    private String targetUrl;

    private HttpMethod method = HttpMethod.POST; // Default method

    private Map<String, String> headers;

    private Object body;
}
