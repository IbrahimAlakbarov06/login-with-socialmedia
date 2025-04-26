package org.example.socialmediabackend.service;

import org.example.socialmediabackend.model.User;
import org.example.socialmediabackend.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class OAuth2UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public OAuth2UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User processOAuthUser(OAuth2User oAuth2User, String provider) {
        String email = extractEmail(oAuth2User, provider);
        String name = extractName(oAuth2User, provider);

        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            return userOptional.get();
        }

        // Create new user
        User user = new User();
        user.setEmail(email);
        // Generate a username based on the name or email
        user.setUsername(generateUsername(name));
        // Generate a random password (user won't need this for OAuth login)
        user.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
        user.setEnabled(true); // OAuth2 users are pre-verified

        return userRepository.save(user);
    }

    private String extractEmail(OAuth2User oAuth2User, String provider) {
        Map<String, Object> attributes = oAuth2User.getAttributes();

        switch (provider) {
            case "google":
                return (String) attributes.get("email");
            case "facebook":
                return (String) attributes.get("email");
            case "apple":
                // Apple's email attribute might be in a different location
                return (String) attributes.get("email");
            default:
                throw new IllegalArgumentException("Unsupported OAuth2 provider: " + provider);
        }
    }

    private String extractName(OAuth2User oAuth2User, String provider) {
        Map<String, Object> attributes = oAuth2User.getAttributes();

        switch (provider) {
            case "google":
                return (String) attributes.get("name");
            case "facebook":
                return (String) attributes.get("name");
            case "apple":
                // Apple might provide the name differently
                String firstName = (String) attributes.getOrDefault("firstName", "");
                String lastName = (String) attributes.getOrDefault("lastName", "");
                return firstName + " " + lastName;
            default:
                throw new IllegalArgumentException("Unsupported OAuth2 provider: " + provider);
        }
    }

    private String generateUsername(String name) {
        // Remove spaces and convert to lowercase
        String baseUsername = name.replaceAll("\\s+", "").toLowerCase();

        // Check if username exists, if so, add a random suffix
        String username = baseUsername;
        int attempt = 1;
        while (userRepository.findByUsername(username).isPresent()) {
            username = baseUsername + attempt;
            attempt++;
        }

        return username;
    }
}