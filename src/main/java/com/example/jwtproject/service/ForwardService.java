package com.example.jwtproject.service;

import com.example.jwtproject.dto.ForwardRequest;
import com.example.jwtproject.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@Service
public class ForwardService {

    private static final Logger logger = LoggerFactory.getLogger(ForwardService.class);

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private WebClient.Builder webClientBuilder;

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${app.forward.default-target-url:https://httpbin.org/anything}") // Example default
    private String defaultTargetUrl;

    @Value("${app.forward.propagate-jwt-header:X-Forwarded-User-Token}")
    private String jwtPropagationHeaderName;

    @Value("${app.forward.propagate-userid-header:X-Forwarded-User-Id}")
    private String userIdPropagationHeaderName;


    /**
     * Forwards the request using RestTemplate.
     *
     * @param forwardRequest      The details of the request to forward.
     * @param authorizationHeader The original Authorization header (Bearer token).
     * @return ResponseEntity containing the response from the target URL.
     */
    public ResponseEntity<?> forwardRequestRestTemplate(ForwardRequest forwardRequest, String authorizationHeader) {
        String targetUrl = forwardRequest.getTargetUrl() != null ? forwardRequest.getTargetUrl() : defaultTargetUrl;
        HttpMethod method = forwardRequest.getMethod() != null ? forwardRequest.getMethod() : HttpMethod.GET;

        HttpHeaders headers = new HttpHeaders();
        // Copy custom headers from the forward request
        if (forwardRequest.getHeaders() != null) {
            forwardRequest.getHeaders().forEach(headers::add);
        }

        // Propagate JWT or User ID
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String jwt = authorizationHeader.substring(7);
            if (jwtUtil.validateJwtToken(jwt)) {
                headers.add(jwtPropagationHeaderName, jwt); // Forward the original JWT
                String userId = jwtUtil.getUserIdFromJwtToken(jwt);
                headers.add(userIdPropagationHeaderName, userId); // Forward User ID
                logger.debug("Forwarding request with JWT and User ID to {}", targetUrl);
            } else {
                 logger.warn("Invalid JWT provided in Authorization header for forwarding.");
            }
        } else {
            logger.debug("Forwarding request without JWT/User ID to {}", targetUrl);
        }

        // Ensure Content-Type is set if there's a body, default to JSON if not specified
        if (forwardRequest.getBody() != null && !headers.containsKey(HttpHeaders.CONTENT_TYPE)) {
            headers.setContentType(MediaType.APPLICATION_JSON);
        }


        HttpEntity<Object> entity = new HttpEntity<>(forwardRequest.getBody(), headers);

        logger.info("Forwarding {} request to {} with RestTemplate", method, targetUrl);

        try {
            ResponseEntity<String> response = restTemplate.exchange(targetUrl, method, entity, String.class);
            logger.info("Successfully forwarded request to {}. Status: {}", targetUrl, response.getStatusCode());
            return response;
        } catch (HttpStatusCodeException e) {
            logger.error("Error forwarding request to {}: {} - {}", targetUrl, e.getStatusCode(), e.getResponseBodyAsString(), e);
            return ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString());
        } catch (Exception e) {
            logger.error("Generic error forwarding request to {}: {}", targetUrl, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error forwarding request: " + e.getMessage());
        }
    }

    /**
     * Forwards the request using WebClient (example, commented out by default in controller).
     *
     * @param forwardRequest      The details of the request to forward.
     * @param authorizationHeader The original Authorization header (Bearer token).
     * @return Mono<ResponseEntity<Object>> containing the response from the target URL.
     */
    public Mono<ResponseEntity<Object>> forwardRequestWebClient(ForwardRequest forwardRequest, String authorizationHeader) {
        String targetUrl = forwardRequest.getTargetUrl() != null ? forwardRequest.getTargetUrl() : defaultTargetUrl;
        HttpMethod method = forwardRequest.getMethod() != null ? forwardRequest.getMethod() : HttpMethod.GET;

        WebClient.RequestBodySpec requestBodySpec = webClientBuilder.build()
                .method(method)
                .uri(targetUrl)
                .headers(httpHeaders -> {
                    if (forwardRequest.getHeaders() != null) {
                        forwardRequest.getHeaders().forEach(httpHeaders::add);
                    }
                    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                        String jwt = authorizationHeader.substring(7);
                         if (jwtUtil.validateJwtToken(jwt)) {
                            httpHeaders.add(jwtPropagationHeaderName, jwt);
                            String userId = jwtUtil.getUserIdFromJwtToken(jwt);
                            httpHeaders.add(userIdPropagationHeaderName, userId);
                             logger.debug("Forwarding request with JWT and User ID to {} using WebClient", targetUrl);
                        } else {
                            logger.warn("Invalid JWT provided in Authorization header for WebClient forwarding.");
                        }
                    } else {
                        logger.debug("Forwarding request without JWT/User ID to {} using WebClient", targetUrl);
                    }
                     // Ensure Content-Type is set if there's a body, default to JSON if not specified
                    if (forwardRequest.getBody() != null && !httpHeaders.containsKey(HttpHeaders.CONTENT_TYPE)) {
                        httpHeaders.setContentType(MediaType.APPLICATION_JSON);
                    }
                });

        WebClient.RequestHeadersSpec<?> requestHeadersSpec;
        if (forwardRequest.getBody() != null) {
            requestHeadersSpec = requestBodySpec.bodyValue(forwardRequest.getBody());
        } else {
            requestHeadersSpec = requestBodySpec;
        }

        logger.info("Forwarding {} request to {} with WebClient", method, targetUrl);

        return requestHeadersSpec.retrieve()
                .toEntity(Object.class) // Using Object.class to handle various response types
                .doOnSuccess(response -> logger.info("Successfully forwarded request to {} with WebClient. Status: {}", targetUrl, response.getStatusCode()))
                .doOnError(error -> logger.error("Error forwarding request to {} with WebClient: {}", targetUrl, error.getMessage(), error))
                .onErrorResume(HttpStatusCodeException.class, e ->
                    Mono.just(ResponseEntity.status(e.getStatusCode()).body(e.getResponseBodyAsString()))
                )
                .onErrorResume(Exception.class, e ->
                    Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error forwarding request: " + e.getMessage()))
                );
    }
}
