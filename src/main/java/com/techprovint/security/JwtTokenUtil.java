package com.techprovint.security;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.codec.binary.Base64;
import org.apache.tomcat.util.codec.binary.StringUtils;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
@Slf4j
public class JwtTokenUtil implements Serializable {

	private static final long serialVersionUID = -2550185165626007488L;
	
	public static final long JWT_TOKEN_VALIDITY = 5*60*60;

    private JsonParser parser = new JsonParser();

	@Value("${jwt.secret}")
	private String secret;

	public String getUsernameFromToken(String token) {
		//return getClaimFromToken(token, Claims::getSubject);
        JsonElement payload = parser.parse(StringUtils.newStringUtf8(Base64.decodeBase64(token)));
        JSONObject payloadJson = new JSONObject(payload.toString());
        String email = payloadJson.getString("email");
        log.info("email: {}", email);
        return email;
	}

	public Date getIssuedAtDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getIssuedAt);
	}

	public Date getExpirationDateFromToken(DecodedJWT jwt) {
        return jwt.getExpiresAt();
		//return getClaimFromToken(token, Claims::getExpiration);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	private Boolean isTokenExpired(DecodedJWT jwt) {
		final Date expiration = getExpirationDateFromToken(jwt);
		log.info("expiration: {}", expiration.toString());
		log.info("now: {}", new Date());
		return expiration.before(new Date());
	}

	private Boolean ignoreTokenExpiration(DecodedJWT jwt) {
		// here you specify tokens, for that the expiration is ignored
		return false;
	}

	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		return doGenerateToken(claims, userDetails.getUsername());
	}

	private String doGenerateToken(Map<String, Object> claims, String subject) {

		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY*1000)).signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	public Boolean canTokenBeRefreshed(DecodedJWT jwt) {
		return (!isTokenExpired(jwt) || ignoreTokenExpiration(jwt));
	}

	public Boolean validateToken(DecodedJWT jwt, UserDetails userDetails) {
		final String username = getUsernameFromToken(jwt.getPayload());
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(jwt));
	}
}