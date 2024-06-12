package auth.com.usuario.Token;


import auth.com.usuario.Model.Usuario;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    @Value("${chave.token}")
    private String palavaChave;

    public String gerarToken(Usuario usuario){
        try{
            Algorithm algoritimo = Algorithm.HMAC256(palavaChave);
            String token = JWT
                    .create()
                    .withIssuer("usuario")
                    .withSubject(usuario.getEmail())
                    .withExpiresAt(gerarDataExpiracao())
                    .sign(algoritimo);
            return token;
        }catch(JWTVerificationException e){
            throw new RuntimeException("Erro ao criar o token!");
        }
    }

    public String validarToken(String token){
        try{
            Algorithm algoritimo = Algorithm.HMAC256(palavaChave);
            return JWT
                    //Comando require para validação do algoritimo contigo na palavraSecreta
                    .require(algoritimo)
                    //Comando withIssuer para validar o assunto condificado no algoritimo.
                    .withIssuer("usuario")
                    //Comando build para criação da validação.
                    .build()
                    .verify(token)
                    .getSubject();
        }catch (JWTVerificationException erro){
            throw new RuntimeException("Não foi possível validar o token");
        }
    }


    public Instant gerarDataExpiracao (){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}



