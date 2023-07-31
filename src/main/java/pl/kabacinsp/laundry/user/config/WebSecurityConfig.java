package pl.kabacinsp.laundry.user.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import pl.kabacinsp.laundry.user.security.AccessDeniedHandlerImpl;
import pl.kabacinsp.laundry.user.security.AuthenticationProvider;
import pl.kabacinsp.laundry.user.security.AuthenticationSuccessHandleImpl;
import pl.kabacinsp.laundry.user.security.LogoutSuccessHandlerImpl;
import pl.kabacinsp.laundry.user.service.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

  @Autowired private UserDetailsServiceImpl customUserDetailsService;

  @Bean
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
    MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
    http.formLogin(withDefaults())
        .authorizeHttpRequests(
            (requests) ->
                requests
                    .requestMatchers(
                        mvcMatcherBuilder.pattern("/"), mvcMatcherBuilder.pattern("/home"))
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .formLogin((form) -> form.loginPage("/login").permitAll())
        .logout(LogoutConfigurer::permitAll);
    return http.build();
  }

  @Bean
  public AccessDeniedHandler accessDeniedHandler() {
    return new AccessDeniedHandlerImpl();
  }

  @Bean
  public LogoutSuccessHandler logoutSuccessHandler() {
    return new LogoutSuccessHandlerImpl();
  }

  @Bean
  public AuthenticationSuccessHandler loginSuccessHandler() {
    return new AuthenticationSuccessHandleImpl();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public DaoAuthenticationProvider authenticationProvider() {
    final DaoAuthenticationProvider bean = new AuthenticationProvider();
    bean.setUserDetailsService(customUserDetailsService);
    bean.setPasswordEncoder(passwordEncoder());
    return bean;
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer(HandlerMappingIntrospector introspector) {
    MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
    return (web) -> web.ignoring().requestMatchers(mvcMatcherBuilder.pattern("/resources/**"));
  }
}
