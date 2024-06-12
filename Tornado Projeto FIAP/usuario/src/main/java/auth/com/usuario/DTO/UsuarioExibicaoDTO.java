package auth.com.usuario.DTO;

import auth.com.usuario.Model.UserRole;
import auth.com.usuario.Model.Usuario;

import java.time.LocalDate;

public record UsuarioExibicaoDTO(

        Long id,
        String nome,
        String email,

        UserRole user,
        LocalDate data
) {
    public UsuarioExibicaoDTO(Usuario usuario){
        this(usuario.getId(), usuario.getNome(), usuario.getEmail(), usuario.getUser(),usuario.getData());
    }

}
