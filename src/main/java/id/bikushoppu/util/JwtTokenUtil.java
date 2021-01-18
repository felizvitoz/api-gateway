package id.bikushoppu.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

import org.springframework.stereotype.Component;

@Component //put this class in bikkushop core
public class JwtTokenUtil implements Serializable {

    private String secret = "rahasia";

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public List<String> getRoles(String token) {
        return getClaimFromToken(token, claims -> (List<String>) claims.get("ROLES"));
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }
}
