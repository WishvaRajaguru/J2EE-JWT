package lk.rajaguru.web.app.security.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Set;

public class JWTUtil {
    //jwt token format - header.payload.secret (these will be encoded)
    //the secret to be used for jwt token
    private static final String JWT_SECRET = "McEtdnfKJDPmChRiBCCwELjrlFZPevibULzW";
    //to ensure the secret is more secure by getting its bite values and turning them into hash
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
    //time for the token to be expired (1 hour - 60 * 60 * 1000) in millis
    private static final long EXPIRES_IN = 3_600_000;

    public static String generateToken(String username, Set<String> roles) {
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + EXPIRES_IN))
                .signWith(SECRET_KEY, Jwts.SIG.HS256)
                .compact();
    }

    public static Jws<Claims> parseToken(String token) throws JwtException {
        return Jwts.parser().verifyWith(SECRET_KEY).build().parseSignedClaims(token);
    }
}
