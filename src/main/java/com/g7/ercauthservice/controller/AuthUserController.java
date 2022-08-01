package com.g7.ercauthservice.controller;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.WebUtils;

import javax.mail.MessagingException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

//import org.springframework.hateoas.server.mvc.WebMvcLinkBuilder;
//import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;

@RestController
@Slf4j
@RequestMapping("/api/auth")
@CrossOrigin(origins = {"https://localhost:3000", "https://erc-ruh.live","https://erc-data-service.herokuapp.com/"}, maxAge = 3600, allowCredentials = "true")
public class AuthUserController {

    @Autowired
    private AuthUserServiceImpl authUserService;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private TokenStoreService tokenStoreService;
    @Autowired
    private MailService mailService;

    @Value("${data.api.signUp}")
    private String userInfoAddURI;
    @Value("${data.api.email}")
    private String userInfoEmailUpdateURI;
    @Value("${data.api.role}")
    private String userInfoRoleUpdateURI;
    @Value("${jwtExpirationMs}")
    private int accessExpirationMs;
    @Value("${jwtRefreshExpirationMs}")
    private int refreshExpirationMs;
    @Value("${cookie.secure}")
    private boolean secure;
    private void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
            .httpOnly(true)
            .secure(secure)
            .path("/api/")
            .maxAge(maxAge)
            .sameSite("None")  // risky
            .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    @GetMapping(value = "/test") //validate
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> test() {
        try {
//            UserInfo userInfo =  new UserInfo();
//            BeanUtils.copyProperties(request,userInfo);
//
//            RestTemplate restTemplate = new RestTemplate();
//            HttpHeaders headers =  new HttpHeaders();
//            String token = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiI1M2Q1M2E2My1mN2RkLTQ2NDgtOWY1OC04N2MyZDk1ZjYxYzgyMDEyNzQ5MzAxIiwiaWF0IjoxNjU3Mz" +
//                    "g5NTU5LCJleHAiOjE2NTc0NzU5NTl9.sZUee3GpmfpHnZPHj3oRLrh2n5mYEWy8BdYSYuTITbZaeR8OeCdWKO-jJKTj2UQUudXIzMuqgWiImuaj-OUlnw";
//
//            headers.add("Authorization","Bearer "+token);
//
//            HttpEntity<String> dataRequest = new HttpEntity<>(headers);
//            String url1 = "http://localhost:8081/api/data/test";
//            System.out.println(dataRequest);
//            ResponseEntity<?> response = restTemplate.exchange(url1, HttpMethod.GET,dataRequest,String.class);
//            System.out.println(response);

            return new ResponseEntity<>("userInfo",HttpStatus.ACCEPTED);
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
            //mailService.sendEmail(email,"Complete the sign up process to ERC", MailType.MAIL_VERIFY,token.getId());
            return new ResponseEntity<>(response,HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }

    @PostMapping("/create-user")
    public ResponseEntity<?> createUser(@RequestBody AuthUserCreateRequest request,@RequestParam String id,HttpServletResponse response) throws Exception {
        AuthUser authUser =  null;
        try {
            if(id == null || !tokenStoreService.exists(id)){
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }
            Token token = tokenStoreService.getTokenByIdAndIssueFor(id);
            authUser = authUserService.add(request.getPassword(),token);
            AuthUserSignInRequest signInRequest = new AuthUserSignInRequest(authUser.getEmail(),request.getPassword());
            JSONObject body = authUserService.generateToken(signInRequest);

            UserInfo userInfo =  new UserInfo();
            BeanUtils.copyProperties(request,userInfo);
            userInfo.setEmail(authUser.getEmail());
            userInfo.setId(authUser.getId());
            userInfo.setRoles(authUser.getRoles());

            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers =  new HttpHeaders();
            headers.add("Authorization","Bearer "+body.getAsString("access"));
            //headers.add("Cookie","access="+body.getAsString("access"));

            HttpEntity<UserInfo> dataRequest = new HttpEntity<>(userInfo,headers);
            System.out.println(dataRequest);
            ResponseEntity<?> dataResponse = restTemplate.exchange(userInfoAddURI, HttpMethod.POST,dataRequest,String.class);

            if(dataResponse.getStatusCodeValue() !=201 ){
                if(authUserService.existAuthUser(authUser.getEmail())){
                    authUserService.remove(authUser.getId());
                    throw new Exception("User not created email : "+authUser.getEmail());
                }
            }

            tokenStoreService.deleteToken(token.getToken());
//            addCookie(response, "access", body.getAsString("access"), accessExpirationMs/1000);
            addCookie(response, "refresh", body.getAsString("refresh"), refreshExpirationMs/1000);
            log.info("user created >> {}",authUser.getEmail());
            return new ResponseEntity<>(body,HttpStatus.CREATED);
        }catch (Exception e){
            e.printStackTrace();
            log.error("error user created >> invalid token or process failed");
            if(authUserService.existAuthUser(authUser.getEmail())){
                authUserService.remove(authUser.getId());
            }
            throw e;
        }
    }

    @PostMapping( "/token/generate")
    public ResponseEntity<?> generateToken(@RequestBody AuthUserSignInRequest request, HttpServletResponse response){
        JSONObject body = authUserService.generateToken(request);
//        addCookie(response, "access", body.getAsString("access"), accessExpirationMs/1000);
        addCookie(response, "refresh", body.getAsString("refresh"), refreshExpirationMs/1000);
        return new ResponseEntity<>(body, HttpStatus.OK);
    }

    @PutMapping("/user/enable/{id}")
    public ResponseEntity<?> changeEnableStateByUserId(@PathVariable String id){
        authUserService.changeEnableState(id);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PutMapping("/user/enable")
    public ResponseEntity<?> changeEnableState(){
        authUserService.changeEnableState(jwtUtils.getUserIdFromRequest());
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PutMapping("/user/lock/{id}")
    public ResponseEntity<?> changeLockStateByUserId(@PathVariable String id){
        authUserService.changeLockState(id);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PutMapping("/user/verified/{id}")
    public ResponseEntity<?> changeVerifiedStateByUserId(@PathVariable String id){
        authUserService.changeVerifiedState(id);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody JSONObject request) {
        //Cookie name = WebUtils.getCookie(request, "refresh");
        //System.out.println(name);
        //String requestRefreshToken = name != null ? name.getValue() : null;//request.getToken();
        String requestRefreshToken = request.getAsString("token");
        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getAuthUser)
                .map(user -> {
                    String token = jwtUtils.generateTokenFromAuthUserId(user.getId());
                    log.info("Successfully return new access token from refresh token");
                    JSONObject response = new JSONObject();
                    response.put("access",token);
                    //addCookie(httpServletResponse, "access", token, 3600);
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
            response.put("isVerified",userDetails.getIsVerified());
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
            //mailService.sendEmail(authUser.getEmail(),"Reset your ERC password", MailType.FORGOT_PASSWORD,token.getId());
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
            return new ResponseEntity<>(HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }

    @PutMapping("/update/email")
    public ResponseEntity<?> updateEmail(@RequestParam String id) throws Exception {

        UpdateEmailRequest request = null;
        try {
            if(id == null){
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }
            String token = tokenStoreService.getTokenByIdAndIssueFor(id, IssueType.FOR_EMAIL_UPDATE).getToken();
            request = jwtUtils.generateUpdateEmailRequestFromToken(token);
            String jwt = authUserService.updateEmail(request);
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers =  new HttpHeaders();
            headers.add("Authorization","Bearer "+jwt);
            headers.add("Cookie","access="+jwt);
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("email",request.getNewEmail());

            HttpEntity<JSONObject> dataRequest = new HttpEntity<>(jsonObject,headers);
            System.out.println(dataRequest);
            ResponseEntity<?> dataResponse = restTemplate.exchange(userInfoEmailUpdateURI, HttpMethod.PUT,dataRequest,String.class);

            if(dataResponse.getStatusCodeValue() !=200 ){
                authUserService.updateEmailRollBack(request);
                throw new Exception("Email not updated : old >> "+request.getOldEmail()+"new >> "+request.getNewEmail());
            }
            tokenStoreService.deleteToken(token);
            return new ResponseEntity<>(request,HttpStatus.OK);
        }catch (Exception e){
            authUserService.updateEmailRollBack(request);
            throw e;
        }
    }

    @PutMapping("/update/password")
    public ResponseEntity<?> updatePassword(@RequestBody UpdatePasswordRequest request){
        try {
            authUserService.updatePassword(jwtUtils.getUserIdFromRequest(), request.getOldPassword(), request.getNewPassword());
            return new ResponseEntity<>(HttpStatus.OK);
        }catch (Exception e){
            throw e;
        }
    }

    @PostMapping("/check/password")
    public ResponseEntity<?> checkPassword(@RequestBody CheckPasswordRequest request){
        try {
            authUserService.passwordCheck(jwtUtils.getUserIdFromRequest(), request.getPassword());
            return new ResponseEntity<>(HttpStatus.ACCEPTED);
        }catch (Exception e){
            throw e;
        }
    }

    @PutMapping("/update/roles")
    public ResponseEntity<?> updateRoles(@RequestBody UpdateRoleRequest request) throws Exception {
        try {
            AuthUser authUserOld = authUserService.getById(request.getId());
            AuthUser authUser =authUserService.updateRoles(request.getRoles(), request.getId());
            String jwt = jwtUtils.generateTokenFromAuthUserId(authUserOld.getId());

            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers =  new HttpHeaders();
            headers.add("Authorization","Bearer "+jwt);
            //headers.add("Cookie","access="+jwt);

            UserRoleUpdateRequest roleUpdateRequest = new UserRoleUpdateRequest(authUser.getId(),authUser.getRoles());
            System.out.println(roleUpdateRequest);
            HttpEntity<UserRoleUpdateRequest> dataRequest = new HttpEntity<>(roleUpdateRequest,headers);
            System.out.println(dataRequest);
            ResponseEntity<?> dataResponse = restTemplate.exchange(userInfoRoleUpdateURI, HttpMethod.PUT,dataRequest,String.class);

            if(dataResponse.getStatusCodeValue() !=200 ){
                authUserService.roleUpdateByUser(authUser,authUserOld.getRoles());
                throw new Exception("Roles are not updated : old >> "+authUser.getRoles()+"new >> "+authUser.getRoles());
            }
            //mailService.sendEmail("gsample590@gmail.com","Updated privileges on ERC", MailType.ROLE_CHANGE);
            return new ResponseEntity<>(HttpStatus.OK);
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
            return new ResponseEntity<>(HttpStatus.ACCEPTED);
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
            body.put("id",authUser.getId());
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
//            addCookie(response, "access", null, 1);
//            addCookie(response, "refresh", null, 1);
            return new ResponseEntity<>(HttpStatus.OK);
        }catch (Exception e){
            throw e;
        }
    }

    @GetMapping("/auth-user/status/{id}")
    public ResponseEntity<?> getAuthUserStatesById(@PathVariable String id){
        return new ResponseEntity<>(authUserService.getUserStatesById(id),HttpStatus.OK);
    }

    @GetMapping("/auth-user/status")
    public ResponseEntity<?> getAuthUserStatesByUserSelf(){

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            UserDetailsImpl user = (UserDetailsImpl) authentication.getPrincipal();
            AuthUserStatusResponse response = authUserService.getUserStatesById(user.getId());
            System.out.println(response);
            return new ResponseEntity<>(response,HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }

    @GetMapping("/auth-user/all")
    public ResponseEntity<?> getAllAuthUser(){
        try {
            return new ResponseEntity<>(authUserService.getAllAuthUser(),HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }

    @GetMapping("/auth-user/un-verified")
    public ResponseEntity<?> getAllUnVerifiedAuthUser(){
        try {
            return new ResponseEntity<>(authUserService.getAllUnVerifiedAuthUsers(false),HttpStatus.OK);
        }catch (Exception e){
            e.printStackTrace();
            throw e;
        }
    }


}
