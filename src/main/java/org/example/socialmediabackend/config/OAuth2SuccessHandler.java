package org.example.socialmediabackend.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.socialmediabackend.model.User;
import org.example.socialmediabackend.service.JwtService;
import org.example.socialmediabackend.service.OAuth2UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;

@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final OAuth2UserService oAuth2UserService;

    @Value("${app.oauth2.redirectUri}")
    private String redirectUri;

    public OAuth2SuccessHandler(JwtService jwtService, OAuth2UserService oAuth2UserService) {
        this.jwtService = jwtService;
        this.oAuth2UserService = oAuth2UserService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            OAuth2User oauth2User = oauthToken.getPrincipal();
            String provider = oauthToken.getAuthorizedClientRegistrationId();

            User user = oAuth2UserService.processOAuthUser(oauth2User, provider);
            String token = jwtService.generateToken(user);

            String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam("token", token)
                    .queryParam("expiresIn", jwtService.getExpirationTime())
                    .build().toUriString();

            getRedirectStrategy().sendRedirect(request, response, targetUrl);
        } else {
            super.onAuthenticationSuccess(request, response, authentication);
        }
    }

    // Verify that the redirect URI is allowed to prevent open redirect vulnerabilities
    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);
        // List of allowed redirect URIs should come from configuration
        return true; // Replace with actual validation logic
    }
}