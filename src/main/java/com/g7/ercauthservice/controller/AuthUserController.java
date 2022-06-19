package com.g7.ercauthservice.controller;

import com.g7.ercauthservice.entity.AuthUser;
import com.g7.ercauthservice.entity.RefreshToken;
import com.g7.ercauthservice.entity.Token;
import com.g7.ercauthservice.enums.IssueType;
import com.g7.ercauthservice.enums.MailType;
import com.g7.ercauthservice.enums.Role;
import com.g7.ercauthservice.exception.EmailEqualException;
import com.g7.ercauthservice.exception.RoleException;
import com.g7.ercauthservice.exception.TokenRefreshException;
import com.g7.ercauthservice.exception.UserAlreadyExistException;
import com.g7.ercauthservice.model.*;
import com.g7.ercauthservice.security.JwtUtils;
import com.g7.ercauthservice.service.RefreshTokenService;
import com.g7.ercauthservice.service.TokenStoreService;
import com.g7.ercauthservice.service.impl.AuthUserServiceImpl;
import com.g7.ercauthservice.service.impl.UserDetailsImpl;
import com.g7.ercauthservice.utility.MailService;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.WebUtils;

import javax.mail.MessagingException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

//import org.springframework.hateoas.server.mvc.WebMvcLinkBuilder;
//import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;

@RestController
@Slf4j
@RequestMapping("/api/auth")
@CrossOrigin(origins = {"http://localhost:3000"},maxAge = 3600,allowCredentials = "true")
public class AuthUserController {

    @Autowired
    private AuthUserServiceImpl authUserService;
    private final AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private TokenStoreService tokenStoreService;
    @Autowired
    private MailService mailService;

    public AuthUserController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    private  Cookie cookie(String name, String value, int MaxAge){
        Cookie cookie = new  Cookie(name, value);
        cookie.setMaxAge(MaxAge);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        return cookie;
    }

    @GetMapping(value = "/test") //validate
   // @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> test() throws MessagingException, IOException {
        try {
            mailService.sendEmail("gsample590@gmail.com","Invitation from ERC", MailType.INVITE_CLERK);
            return new ResponseEntity<>(HttpStatus.ACCEPTED);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }

    @PostMapping("/create-user/invite/reviewer/token")
    public ResponseEntity<?> sendCreateReviewerVerificationToken(@RequestBody JSONObject request) throws MessagingException, IOException {
        try {
            String email = request.getAsString("email");
            if(authUserService.existAuthUser(email)){
                throw  new UserAlreadyExistException(email+" is already exists..!");
            }
            String tokenString = jwtUtils.generateTokenFromEmail(email);
            Token token = tokenStoreService.storeToken(new Token(tokenString, IssueType.FOR_INVITE_REVIEWER,"new reviewer request"));
            JSONObject response = new JSONObject();
            response.put("token",token.getId());
            //mailService.sendEmail("gsample590@gmail.com","Invitation from ERC", MailType.INVITE_REVIEWER);
            return new ResponseEntity<>(response,HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }

    @PostMapping("/create-user/invite/clerk/token")
    public ResponseEntity<?> sendCreateClerkVerificationToken(@RequestBody JSONObject request) throws MessagingException, IOException {
        try {
            String email = request.getAsString("email");
            if(authUserService.existAuthUser(email)){
                throw  new UserAlreadyExistException(email+" is already exists..!");
            }
            if(authUserService.checkRoleUnique(Role.ROLE_CLERK)){
                throw new RoleException("This is unique role");
            }
            String tokenString = jwtUtils.generateTokenFromEmail(email);
            Token token = tokenStoreService.storeToken(new Token(tokenString, IssueType.FOR_INVITE_CLERK,"new reviewer request"));
            JSONObject response = new JSONObject();
            response.put("token",token.getId());
            //mailService.sendEmail("gsample590@gmail.com","Invitation from ERC", MailType.INVITE_CLERK);
            return new ResponseEntity<>(response,HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }

    @PostMapping("/create-user/invite/secretary/token")
    public ResponseEntity<?> sendCreateSecretaryVerificationToken(@RequestBody JSONObject request) throws MessagingException, IOException {
        try {
            String email = request.getAsString("email");
            if(authUserService.existAuthUser(email)){
                throw  new UserAlreadyExistException(email+" is already exists..!");
            }
            if(authUserService.checkRoleUnique(Role.ROLE_SECRETARY)){
                throw new RoleException("This is unique role");
            }
            String tokenString = jwtUtils.generateTokenFromEmail(email);
            Token token = tokenStoreService.storeToken(new Token(tokenString, IssueType.FOR_INVITE_SECRETARY,"new reviewer request"));
            JSONObject response = new JSONObject();
            response.put("token",token.getId());
            //mailService.sendEmail("gsample590@gmail.com","Invitation from ERC", MailType.INVITE_SECRETARY);
            return new ResponseEntity<>(response,HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }
    @PostMapping("/create-user/token")
    public ResponseEntity<?> sendCreateUserVerificationToken(@RequestBody JSONObject request) throws MessagingException, IOException {
        try {
            String email = request.getAsString("email");
            if(authUserService.existAuthUser(email)){
                throw  new UserAlreadyExistException(email+" is already exists..!");
            }
            String tokenString = jwtUtils.generateTokenFromEmail(request.getAsString("email"));
            Token token = tokenStoreService.storeToken(new Token(tokenString, IssueType.FOR_EMAIL_VERIFICATION,"new user request"));
            JSONObject response = new JSONObject();
            response.put("token",token.getId());
            //mailService.sendEmail("gsample590@gmail.com","Complete the sign up process to ERC", MailType.MAIL_VERIFY);
            return new ResponseEntity<>(response,HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }

    @PostMapping("/create-user")
    public ResponseEntity<?> createUser(@RequestBody AuthUserCreateRequest request,@RequestParam String id) throws Exception {
        try {
            if(id == null || !tokenStoreService.exists(id)){
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }
            Token token = tokenStoreService.getTokenByIdAndIssueFor(id);
            AuthUser authUser = authUserService.add(request,token);
            tokenStoreService.deleteToken(token.getToken());
            log.info("user created >> {}",authUser.getEmail());
            return new ResponseEntity<>(HttpStatus.CREATED);
        }catch (Exception e){
            e.printStackTrace();
            log.error("error user created >> invalid token or process failed");
            throw e;
        }
    }

    @PostMapping(value = "/token/generate")
    public ResponseEntity<?> generateToken(@RequestBody AuthUserSignInRequest request, HttpServletResponse response){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId(),jwt);

        JSONObject body = new JSONObject();
        body.put("access",jwt);
        body.put("refresh",refreshToken.getToken());
        body.put("roles",authUserService.setRoles(roles));

        response.addCookie(cookie("access",jwt,3600));
        response.addCookie(cookie("refresh",refreshToken.getToken(),3600*24));
        return new ResponseEntity<>(body, HttpStatus.OK);
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request,HttpServletResponse httpServletResponse) {
        Cookie name = WebUtils.getCookie(request, "refresh");
        String requestRefreshToken = name != null ? name.getValue() : null;//request.getToken();
        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getAuthUser)
                .map(user -> {
                    String token = jwtUtils.generateTokenFromAuthUserId(user.getId());
                    log.info("Successfully return new access token from refresh token");
                    JSONObject response = new JSONObject();
                    response.put("access",token);
                    httpServletResponse.addCookie(cookie("access",token,3600));
                    return new ResponseEntity<>(response,HttpStatus.OK);
                })
                .orElseThrow(() ->{
                    log.info("Refresh token is not in database ! token is {}",requestRefreshToken);
                    return new TokenRefreshException(requestRefreshToken,"Refresh token is not in database!");
                });
    }

    @PostMapping("/token/validate")
    public ResponseEntity<?> validateToken(@RequestBody JSONObject request){
        try {
            String id = jwtUtils.getUserIdFromJwtToken(request.getAsString("token"));
            UserDetailsImpl userDetails = UserDetailsImpl.build(authUserService.getById(id));
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            JSONObject response = new JSONObject();
            response.put("valid",true);
            response.put("id",id);
            response.put("authorities",roles);
            return new ResponseEntity<>(response,HttpStatus.OK);
        }catch (Exception e){
            JSONObject response = new JSONObject();
            response.put("valid",false);
            response.put("id",null);
            response.put("error",e.getMessage());
            return new ResponseEntity<>(response,HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/update/email/send/token")
    public ResponseEntity<?> sendUpdateEmailVerificationToken(@RequestBody UpdateEmailRequest request) {
        try {
            AuthUser authUser = authUserService.getById(jwtUtils.getUserIdFromRequest());
            if(!authUser.getEmail().equals(request.getOldEmail())){
                throw new EmailEqualException("Registered mail and given mail have conflict");
            }
            if(request.getNewEmail().equals(request.getOldEmail())){
                throw new EmailEqualException("Old email and new email are same");
            }
            String tokenString = jwtUtils.generateTokenFromUpdateEmail(jwtUtils.getUserIdFromRequest(), request);
            Token token = tokenStoreService.storeToken(new Token(tokenString, IssueType.FOR_EMAIL_UPDATE, authUser.getId()));
            JSONObject response = new JSONObject();
            response.put("token",token.getId());
            return new ResponseEntity<>(response,HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
           throw e;
        }
    }

    @PostMapping("/update/password/forgot/token")
    public ResponseEntity<?> sendForgotPasswordVerificationToken(@RequestBody JSONObject request) throws MessagingException, IOException {
        try {
            AuthUser authUser = authUserService.getAuthUserByEmail(request.getAsString("email"));
            String tokenString = jwtUtils.generateTokenFromEmail(authUser.getEmail());
            Token token = tokenStoreService.storeToken(new Token(tokenString, IssueType.FOR_FORGOT_PASSWORD, authUser.getId()));
            JSONObject response = new JSONObject();
            response.put("token",token.getId());
            //mailService.sendEmail("gsample590@gmail.com","Reset your ERC password", MailType.FORGOT_PASSWORD);
            return new ResponseEntity<>(response,HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }

    @PostMapping("/update/password/forgot")
    public ResponseEntity<?> sendForgotPasswordVerificationToken(@RequestParam String id,@RequestBody ForgotPasswordRequest request) throws Exception {
        try {
            if(id == null || !tokenStoreService.exists(id)){
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }
            String token = tokenStoreService.getTokenByIdAndIssueFor(id, IssueType.FOR_FORGOT_PASSWORD).getToken();
            String email = jwtUtils.generateEmailFromToken(token);
            authUserService.forgotPassword(email,request);
            tokenStoreService.deleteToken(token);
            return new ResponseEntity<>(email,HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }

    @PostMapping("/update/email")
    public ResponseEntity<?> updateEmail(@RequestParam String id) throws Exception {
        try {
            if(id == null){
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }
            String token = tokenStoreService.getTokenByIdAndIssueFor(id, IssueType.FOR_EMAIL_UPDATE).getToken();
            UpdateEmailRequest request = jwtUtils.generateUpdateEmailRequestFromToken(token);
            authUserService.updateEmail(request);
            tokenStoreService.deleteToken(token);
            return new ResponseEntity<>(request,HttpStatus.OK);
        }catch (Exception e){
            throw e;
        }
    }

    @PostMapping("/update/password")
    public ResponseEntity<?> updatePassword(@RequestBody UpdatePasswordRequest request){
        try {
            authUserService.updatePassword(jwtUtils.getUserIdFromRequest(), request.getOldPassword(), request.getNewPassword());
            return new ResponseEntity<>(jwtUtils.getUserIdFromRequest(),HttpStatus.OK);
        }catch (Exception e){
            throw e;
        }
    }

    @PostMapping("/update/roles")
    public ResponseEntity<?> updateRoles(@RequestBody UpdateRoleRequest request) throws MessagingException, IOException {
        try {
            authUserService.updateRoles(request.getRoles(),jwtUtils.getUserIdFromRequest());
            //mailService.sendEmail("gsample590@gmail.com","Updated privileges on ERC", MailType.ROLE_CHANGE);
            return new ResponseEntity<>(jwtUtils.getUserIdFromRequest(),HttpStatus.OK);
        }catch (Exception e){
            throw e;
        }
    }

    @PostMapping("/request/validate")
    public ResponseEntity<?> requestValidate(@RequestParam String id){
        try {
            if(!tokenStoreService.exists(id)){
                return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            }
            return new ResponseEntity<>(HttpStatus.FOUND);
        }catch (Exception e){
            throw e;
        }
    }

    @GetMapping("/current-user")
    public ResponseEntity<?> getCurrentUser(){
        try {
            AuthUser authUser = authUserService.getById(jwtUtils.getUserIdFromRequest());
            UserDetailsImpl userDetails = UserDetailsImpl.build(authUser);
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            JSONObject body = new JSONObject();
            body.put("email",authUser.getEmail());
            body.put("roles",authUserService.setRoles(roles));
            return new ResponseEntity<>(body,HttpStatus.OK);
        }catch (Exception e){
            throw e;
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response){
        try {
            refreshTokenService.deleteByUserId(jwtUtils.getUserIdFromRequest());
            response.addCookie(cookie("access",null,0));
            response.addCookie(cookie("refresh",null,0));
            return new ResponseEntity<>(HttpStatus.OK);
        }catch (Exception e){
            throw e;
        }
    }

}
