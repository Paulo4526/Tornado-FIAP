package auth.com.usuario.Service;

import auth.com.usuario.DTO.UsuarioCadastroDTO;
import auth.com.usuario.DTO.UsuarioExibicaoDTO;
import auth.com.usuario.Exceptions.UserNaoEncontrado;
import auth.com.usuario.Model.Usuario;
import auth.com.usuario.Repository.UsuarioRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UsuarioService {

    @Autowired
    private UsuarioRepository usuarioRepository;
    public UsuarioExibicaoDTO cadastrarUsuario (UsuarioCadastroDTO usuarioCadastroDTO){
        String criptografia = new BCryptPasswordEncoder().encode(usuarioCadastroDTO.senha());

        Usuario usuario = new Usuario();
        BeanUtils.copyProperties(usuarioCadastroDTO, usuario);
        usuario.setSenha(criptografia);

        Usuario usuarioSalvo = usuarioRepository.save(usuario);
        return new UsuarioExibicaoDTO(usuarioSalvo);
    }

    public Page<UsuarioExibicaoDTO> listarTodos (Pageable pageable){
        return usuarioRepository.findAll(pageable) .map(UsuarioExibicaoDTO::new);
    }

    public UsuarioExibicaoDTO atualizar (Usuario usuario){
        Optional<Usuario> optionalUsuario = usuarioRepository.findById(usuario.getId());

        if(optionalUsuario.isPresent()){
            usuarioRepository.save(usuario);
            return new UsuarioExibicaoDTO(usuario);
        }else{
            throw new UserNaoEncontrado("Usuario não existe");
        }
    }


    public void excluir (Long id){
        Optional<Usuario> usuarioOptional = usuarioRepository.findById(id);
        if(usuarioOptional.isPresent()){
            usuarioRepository.delete(usuarioOptional.get());
        }else{
            throw new UserNaoEncontrado("Usuario não existe!");
        }
    }

}
