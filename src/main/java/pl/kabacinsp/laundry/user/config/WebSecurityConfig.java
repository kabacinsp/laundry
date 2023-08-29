package pl.kabacinsp.laundry.user.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import pl.kabacinsp.laundry.user.security.*;
import pl.kabacinsp.laundry.user.security.jwt.AuthTokenFilter;
import pl.kabacinsp.laundry.user.security.jwt.JwtAuthEntryPoint;
import pl.kabacinsp.laundry.user.service.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig implements WebMvcConfigurer {

  @Override
  public void addCorsMappings(CorsRegistry registry) {
    registry
        .addMapping("/auth/**")
        .allowedOrigins("https://localhost:4200")
        .allowedMethods("PUT", "GET", "DELETE", "OPTIONS", "PATCH", "POST")
        .allowCredentials(true)
        .maxAge(3600);
  }

  @Autowired private UserDetailsServiceImpl customUserDetailsService;
  @Autowired private JwtAuthEntryPoint unauthorizedHandler;

  @Bean
  public AuthTokenFilter authenticationJwtTokenFilter() {
    return new AuthTokenFilter();
  }

  @Bean
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
    MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);

    http.csrf(AbstractHttpConfigurer::disable)
        .formLogin(form -> form.loginPage("/login").permitAll())
        .authorizeHttpRequests(
            (auth) ->
                auth.requestMatchers(mvcMatcherBuilder.pattern("/auth/**"))
                    .permitAll()
                    .requestMatchers(mvcMatcherBuilder.pattern("/favicon.ico"))
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .authenticationProvider(authenticationProvider())
        .addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
        .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public DaoAuthenticationProvider authenticationProvider() {
    final DaoAuthenticationProvider bean = new AuthenticationProviderImpl();
    bean.setUserDetailsService(customUserDetailsService);
    bean.setPasswordEncoder(passwordEncoder());
    return bean;
  }

  @Bean
  public AuthenticationManager authManager(HttpSecurity http) throws Exception {
    return http.getSharedObject(AuthenticationManagerBuilder.class)
        .authenticationProvider(authenticationProvider())
        .build();
  }

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer(HandlerMappingIntrospector introspector) {
    MvcRequestMatcher.Builder mvcMatcherBuilder = new MvcRequestMatcher.Builder(introspector);
    return (web) -> web.ignoring().requestMatchers(mvcMatcherBuilder.pattern("/resources/**"));
  }
}
