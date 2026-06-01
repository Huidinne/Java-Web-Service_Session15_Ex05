package org.example.ex_05.controller;

import org.example.ex_05.model.dto.request.AuthRequestDTO;
import org.example.ex_05.model.dto.response.AuthResponseDTO;
import org.example.ex_05.model.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final Map<String, User> users = new HashMap<>();

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<AuthResponseDTO> register(
            @RequestBody AuthRequestDTO request) {

        if (users.containsKey(request.getUsername())) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(new AuthResponseDTO("Username already exists"));
        }

        String encodedPassword =
                passwordEncoder.encode(request.getPassword());

        User user = new User(
                request.getUsername(),
                encodedPassword
        );

        users.put(user.getUsername(), user);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(new AuthResponseDTO("Register successful"));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(
            @RequestBody AuthRequestDTO request) {

        User user = users.get(request.getUsername());

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponseDTO("Invalid username or password"));
        }

        boolean match = passwordEncoder.matches(
                request.getPassword(),
                user.getPassword()
        );

        if (!match) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponseDTO("Invalid username or password"));
        }

        return ResponseEntity
                .ok(new AuthResponseDTO("Login successful"));
    }
}