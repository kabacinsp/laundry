package pl.kabacinsp.laundry;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import pl.kabacinsp.laundry.user.dto.User;
import pl.kabacinsp.laundry.user.repositories.UserRepository;

import java.util.stream.Stream;

@ComponentScan
@SpringBootApplication
public class LaundryApplication {

	public static void main(String[] args) {
		SpringApplication.run(LaundryApplication.class, args);
	}

	@Bean
	CommandLineRunner init(UserRepository userRepository) {
		return args -> {
			Stream.of("test@user.com", "test@admin.com").forEach(name -> {
				userRepository.save(new User(name, "Bozenka12*"));
			});
			userRepository.findAll().forEach(System.out::println);
		};
	}
}
