package com.g7.ercauthservice.jwt;

import com.g7.ercauthservice.model.UpdateEmailRequest;
import com.g7.ercauthservice.service.impl.UserDetailsImpl;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@Component
@Slf4j
public class JwtUtils {

    //@Value("${jwtSecresaat}")
    @Value("${jwtSecret_auth}")
    private String jwtSecret_auth;

    @Value("${jwtSecret_email}")
    private String jwtSecret_email;
    private final HttpServletRequest request;
    @Value("${jwtExpirationMs}")
    private int jwtExpirationMs;

    public JwtUtils(HttpServletRequest request) {
        this.request = request;
    }

    //====================================auth related jwt configs ===============================
    public String generateTokenFromAuthUserId(String id){
        return Jwts.builder().setSubject(id).
                setIssuedAt(new Date())
                .setExpiration(new Date((new Date().getTime()+jwtExpirationMs)))
                .signWith(SignatureAlgorithm.HS512,jwtSecret_auth)
                .compact();
    }
    public String generateJwtToken(UserDetailsImpl userPrincipal){
        return generateTokenFromAuthUserId(userPrincipal.getId());
    }
    public String getUserIdFromJwtToken(String token){
        return Jwts.parser().setSigningKey(jwtSecret_auth).parseClaimsJws(token).getBody().getSubject();
    }
    private String parseJwt(HttpServletRequest request){
        String headerAuth = request.getHeader("Authorization");

        if(StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")){
            return headerAuth.substring(7);
        }
        return null;
    }
    public String getUserIdFromRequest(){
        return getUserIdFromJwtToken(parseJwt(request));
    }

    //====================================end auth related jwt configs ===============================

    //=====================================mail verification jwt config =============================
    public String generateTokenFromUpdateEmail(String id, UpdateEmailRequest request){
        return Jwts.builder().setSubject(id).
                claim("old",request.getOldEmail()).
                claim("new",request.getNewEmail()).
                setIssuedAt(new Date())
                .setExpiration(new Date((new Date().getTime()+jwtExpirationMs)))
                .signWith(SignatureAlgorithm.HS512,jwtSecret_email)
                .compact();
    }

    public UpdateEmailRequest generateUpdateEmailRequestFromToken(String token){
        String id = Jwts.parser().setSigningKey(jwtSecret_email).parseClaimsJws(token).getBody().getSubject();
        String old= Jwts.parser().setSigningKey(jwtSecret_email).parseClaimsJws(token).getBody().get("old").toString();
        String new_e= Jwts.parser().setSigningKey(jwtSecret_email).parseClaimsJws(token).getBody().get("new").toString();
        return new UpdateEmailRequest(id,old,new_e);
    }
    //=====================================end mail verification jwt config =============================

    //=====================================mail forgot password jwt config =============================
    public String generateTokenFromEmail(String email){
        return Jwts.builder().setSubject(email).
                setIssuedAt(new Date())
                .setExpiration(new Date((new Date().getTime()+jwtExpirationMs)))
                .signWith(SignatureAlgorithm.HS512,jwtSecret_email)
                .compact();
    }

    public String generateEmailFromToken(String token){
        return Jwts.parser().setSigningKey(jwtSecret_email).parseClaimsJws(token).getBody().getSubject();
    }
    //=====================================end mail forgot password jwt config =============================
    public boolean validateJwtToken(String authToken){
        try{
            Jwts.parser().setSigningKey(jwtSecret_auth).parseClaimsJws(authToken);
            return true;
        }catch (SignatureException e){
            log.error("Invalid JWT signature: {}",e.getMessage());
        }catch (MalformedJwtException e){
            log.error("Invalid JWT token: {}",e.getMessage());
        }catch (ExpiredJwtException e){
            log.error("JWT token is expired: {}",e.getMessage());
        }catch (UnsupportedJwtException e){
            log.error("JWT token is unsupported: {}",e.getMessage());
        }catch(IllegalArgumentException e){
            log.error("JWT claims string is empty: {}",e.getMessage());
        }

        return false;
    }
}
