package com.example.clipboardshield.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class OtpController {

    // Thread-safe in-memory store for user OTP codes
    private final Map<String, String> otpStore = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Endpoint to handle user authentication (Sign In / Register)
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> authenticateUser(@RequestBody Map<String, String> credentials) {
        String email = credentials.get("email");
        String password = credentials.get("password");

        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "success", false,
                "message", "Email and password are required."
            ));
        }

        return ResponseEntity.ok(Map.of(
            "success", true,
            "message", "Authentication successful.",
            "user", email,
            "token", "mock-jwt-token-gold-shield"
        ));
    }

    /**
     * Endpoint to generate a secure 6-digit WebOTP authentication code
     */
    @PostMapping("/generate-otp")
    public ResponseEntity<Map<String, String>> generateOtp(@RequestBody Map<String, String> request) {
        String userId = request.getOrDefault("userId", "default-user");

        // Generate cryptographically strong 6-digit OTP
        String otp = String.format("%06d", secureRandom.nextInt(1_000_000));
        otpStore.put(userId, otp);

        return ResponseEntity.ok(Map.of(
            "status", "success",
            "message", "OTP generated successfully.",
            "otp", otp
        ));
    }

    /**
     * Endpoint to verify the submitted OTP code
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<Map<String, Object>> verifyOtp(@RequestBody Map<String, String> request) {
        String userId = request.getOrDefault("userId", "default-user");
        String inputOtp = request.get("otp");

        String validOtp = otpStore.get(userId);

        if (validOtp != null && validOtp.equals(inputOtp)) {
            otpStore.remove(userId); // Consume OTP after single use
            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Authorization successful! WebOTP direct isolation verified."
            ));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "success", false,
                "message", "Invalid or expired authorization code."
            ));
        }
    }
}