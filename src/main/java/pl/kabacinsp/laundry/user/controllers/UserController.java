package pl.kabacinsp.laundry.user.controllers;

import jakarta.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import pl.kabacinsp.laundry.user.controllers.request.LoginRequest;
import pl.kabacinsp.laundry.user.controllers.request.SignupRequest;
import pl.kabacinsp.laundry.user.controllers.response.MessageResponse;
import pl.kabacinsp.laundry.user.controllers.response.UserInfoResponse;
import pl.kabacinsp.laundry.user.dto.RoleType;
import pl.kabacinsp.laundry.user.dto.User;
import pl.kabacinsp.laundry.user.dto.UserRole;
import pl.kabacinsp.laundry.user.repositories.RoleRepository;
import pl.kabacinsp.laundry.user.repositories.UserRepository;
import pl.kabacinsp.laundry.user.security.jwt.JwtAuthentication;
import pl.kabacinsp.laundry.user.service.UserDetailsServiceImpl;
import pl.kabacinsp.laundry.user.utils.UserImpl;

@RestController
@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600)
@RequestMapping("/auth")
public class UserController {

  @Autowired AuthenticationManager authenticationManager;

  @Autowired private UserRepository userRepository;

  @Autowired private PasswordEncoder passwordEncoder;

  @Autowired RoleRepository roleRepository;

  @Autowired JwtAuthentication jwtAuthentication;

  @Autowired private UserDetailsServiceImpl customUserDetailsService;

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    System.out.println("Login request");
    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    UserImpl userDetails = (UserImpl) authentication.getPrincipal();

    ResponseCookie jwtCookie = jwtAuthentication.generateJwtCookie(loginRequest.getUsername());

    List<String> roles =
        authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList());

    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
        .body(
            new UserInfoResponse(
                userDetails.getUser().getId(),
                userDetails.getUsername(),
                userDetails.getUsername(),
                roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.findByEmail(signUpRequest.getEmail()) != null) {
      return ResponseEntity.badRequest()
          .body(new MessageResponse("Error: Username is already taken!"));
    }

    // Create new user's account
    User user =
        new User(signUpRequest.getEmail(), passwordEncoder.encode(signUpRequest.getPassword()));

    Set<String> strRoles = signUpRequest.getRole();
    Set<UserRole> roles = new HashSet<>();

    if (strRoles == null) {
      UserRole userRole =
          roleRepository
              .findByName(RoleType.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(
          role -> {
            switch (role) {
              case "admin" -> {
                UserRole adminRole =
                    roleRepository
                        .findByName(RoleType.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(adminRole);
              }
              case "mod" -> {
                UserRole modRole =
                    roleRepository
                        .findByName(RoleType.ROLE_MODERATOR)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(modRole);
              }
              default -> {
                UserRole userRole =
                    roleRepository
                        .findByName(RoleType.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(userRole);
              }
            }
          });
    }

    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

  @PostMapping("/signout")
  public ResponseEntity<?> logoutUser() {
    ResponseCookie cookie = jwtAuthentication.getCleanJwtCookie();
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE, cookie.toString())
        .body(new MessageResponse("You've been signed out!"));
  }
}
