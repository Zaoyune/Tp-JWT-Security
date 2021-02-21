package com.example.securityservice.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.securityservice.sec.JWTUtil;
import com.example.securityservice.sec.entities.AppRole;
import com.example.securityservice.sec.entities.AppUser;
import com.example.securityservice.sec.service.AccountService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRestControlleR {
    private AccountService accountService;

    public AccountRestControlleR(AccountService accountService) {
        this.accountService = accountService;
    }
    @GetMapping(path = "/users")
    //@PostAuthorize("hasAuthority('USER')")
    @PreAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){
        return accountService.listUsers();
    }
    @PostMapping(path = "/users")
    @PreAuthorize("hasAuthority('ADMIN')")
    //@PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }
    @PostMapping(path = "/roles")
    //@PostAuthorize("hasAuthority('ADMIN')")
    @PreAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }
    @PostMapping(path = "/AddRoleToUser")
    public void AddRoleToUser(@RequestBody RoleUserForm roleUserForm){
         accountService.addRoleToUser(roleUserForm.getUserName(),roleUserForm.getRoleName());
    }
    @GetMapping(path="/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response)throws Exception{{
        String authToken=request.getHeader(JWTUtil.AUTH_HEADER);
        //on cherche si ce refresh-token existe deja puis on check si son access-token n'est pas dans la black list après on crée un nouveau access-token
        if(authToken!=null && authToken.startsWith(JWTUtil.PREFIX))
            try {
                String jwtRefreshToken = authToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256(JWTUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();//créer cet algorithm ou bien ce token
                DecodedJWT decodedJWT = jwtVerifier.verify(jwtRefreshToken);
                String username=decodedJWT.getSubject();
                AppUser appUser=accountService.loadUserByUsername(username);
                String NewJwtAccessToken= JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JWTUtil.EXPIRE_ACCESS_TOKEN))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);


                Map<String,String> idToken=new HashMap<>();
                idToken.put("access-token",NewJwtAccessToken);
                idToken.put("refresh-token",jwtRefreshToken);
                //response.setHeader("Authorization",jwtAccessToken);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);
                //envoyer l'objet sous format json au coeur de la reponse https
            }catch(Exception e) {
                throw e;
            }
        else{
            throw new RuntimeException("Refresh-Token required!!!!!");
        }
    }
    }
    @GetMapping(path = "/profile")
    public AppUser profile(Principal principal){
        return accountService.loadUserByUsername(principal.getName());
    }
}
@Data
class RoleUserForm{
    private String userName;
    private String roleName;
}
