package com.url.shortener.service.jwt;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // This class will be used to intercept requests and validate JWT tokens.
    // It will extend OncePerRequestFilter to ensure that the filter is applied once per request.
    // The actual implementation of the filter logic will be added later.

    @Autowired
    private JwtUtils jwtTokenProvider; 

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Logic to extract and validate JWT token from the request header
        // If valid, set the authentication in the security context
        // If invalid, send an error response

        try {
            // Extract JWT token from the request header
            String jwt = jwtTokenProvider.getJwtFromHeader(request);
            if (jwtTokenProvider != null && jwtTokenProvider.validateJwtToken(jwt)) {
                String username = jwtTokenProvider.getUserNameFromJwtToken(jwt);
                // Here you would typically load the user details from the database or user service
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
                if (userDetails != null) {
                    UsernamePasswordAuthenticationToken authentication = 
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }

        } catch (Exception e) {
            // Handle exceptions related to JWT processing
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
            return;
        }
    }
}
