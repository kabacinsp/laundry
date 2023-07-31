package pl.kabacinsp.laundry.user.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import pl.kabacinsp.laundry.user.dto.User;
import pl.kabacinsp.laundry.user.repositories.UserRepository;

@RestController
//@CrossOrigin(origins = "http://localhost:4200")
public class UserController {

  @Autowired
  private UserRepository userRepository;

  @Autowired private PasswordEncoder passwordEncoder;

  @GetMapping("/users")
  public ResponseEntity<?> getUsers() {

    return ResponseEntity.ok("Ale fajnie");
  }

  @PostMapping("/users")
  public void addUser(@RequestBody User user) {
    userRepository.save(user);
  }

  @PostMapping("/login")
  public ResponseEntity<?> login(@RequestBody User user) {
    System.out.println("Login user " + user.getEmail());
    User user1 = userRepository.findByEmail(user.getEmail());
    if (user1 != null) {
      String password = user.getPassword();
      String encodedPassword = user1.getPassword();
      if (passwordEncoder.matches(password, encodedPassword)) {
        userRepository
            .findOneByEmailAndPassword(user.getEmail(), encodedPassword)
            .ifPresentOrElse(
                value -> ResponseEntity.status(HttpStatusCode.valueOf(200)).body("Authentication successfull"), ResponseEntity::notFound);
      } else {
          ResponseEntity.status(HttpStatusCode.valueOf(401)).body("Password not match");
      }
    }
    return ResponseEntity.status(HttpStatusCode.valueOf(403)).body("E-mail not exist");
  }
}
