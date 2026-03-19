package com.auth.authservice.service;

import com.auth.authservice.entity.Role;
import com.auth.authservice.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private JwtService jwtService;

    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private static final long EXPIRATION = 86400000L;

    private User testUser;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secretKey", SECRET_KEY);
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", EXPIRATION);

        testUser = User.builder()
                .id(1L)
                .firstName("Test")
                .lastName("User")
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .build();
    }

    @Test
    void generateToken_shouldReturnNonNullToken() {
        String token = jwtService.generateToken(testUser);
        assertThat(token).isNotNull().isNotBlank();
    }

    @Test
    void extractUsername_shouldReturnCorrectEmail() {
        String token = jwtService.generateToken(testUser);
        String username = jwtService.extractUsername(token);
        assertThat(username).isEqualTo(testUser.getEmail());
    }

    @Test
    void isTokenValid_withValidToken_shouldReturnTrue() {
        String token = jwtService.generateToken(testUser);
        assertTrue(jwtService.isTokenValid(token, testUser));
    }

    @Test
    void isTokenValid_withDifferentUser_shouldReturnFalse() {
        String token = jwtService.generateToken(testUser);

        User anotherUser = User.builder()
                .id(2L)
                .firstName("Another")
                .lastName("User")
                .email("another@example.com")
                .password("encodedPassword")
                .role(Role.USER)
                .build();

        assertFalse(jwtService.isTokenValid(token, anotherUser));
    }

    @Test
    void isTokenValid_withExpiredToken_shouldReturnFalse() {
        JwtService shortLivedJwtService = new JwtService();
        ReflectionTestUtils.setField(shortLivedJwtService, "secretKey", SECRET_KEY);
        ReflectionTestUtils.setField(shortLivedJwtService, "jwtExpiration", -1000L); // already expired

        String expiredToken = shortLivedJwtService.generateToken(testUser);
        assertFalse(shortLivedJwtService.isTokenValid(expiredToken, testUser));
    }

    @Test
    void getExpirationTime_shouldReturnConfiguredExpiration() {
        assertThat(jwtService.getExpirationTime()).isEqualTo(EXPIRATION);
    }
}
