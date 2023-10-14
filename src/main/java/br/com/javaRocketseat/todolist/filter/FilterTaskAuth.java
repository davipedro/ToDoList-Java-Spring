package br.com.javaRocketseat.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.javaRocketseat.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

            var servletPatch = request.getServletPath();

            if (servletPatch.startsWith("/tasks/")) {
                // Pegar a autenticacao (usuario e senha)
                var authorization = request.getHeader("Authorization");
                System.out.println("authorization: " + authorization);
                
                var authEncoded = authorization.substring("Basic".length()).trim();
                
                byte[] authDecode = Base64.getDecoder().decode(authEncoded);
                
                var authString = new String(authDecode);
                //var authString = String.valueOf(authDecode); ver pq nao funciona com esse

                String[] credentials = authString.split(":");
                String username = credentials[0];
                String password = credentials[1];

                System.out.println("Authorization");
                System.out.println(username);
                System.out.println(password);

                // Validar usuario
                var user = this.userRepository.findByUsername(username);
                if (user == null) {
                    response.sendError(401);
                } else {
                    // Validar senha
                    var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword()); //verifica se o hash esta batendo com a senha fornecida

                    // Segue viagem
                    
                    if (passwordVerify.verified) {
                        request.setAttribute("idUser", user.getId());
                        filterChain.doFilter(request, response);    
                    } else{
                        response.sendError(401);
                    }
                
                }
            }else {
                filterChain.doFilter(request, response);
            }

            

    }
    
}
