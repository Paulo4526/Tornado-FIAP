package auth.com.usuario.Repository;

import auth.com.usuario.Model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {

    //Nessa aplicações somente iremos procurar por todos, pelo nome e id permitido para os ADM's
    public Optional<Usuario> findById(Long id);
    public UserDetails findByEmail (String email);
}
