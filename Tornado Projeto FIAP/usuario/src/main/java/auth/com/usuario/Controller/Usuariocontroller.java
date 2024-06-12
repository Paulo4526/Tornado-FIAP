package auth.com.usuario.Controller;

import auth.com.usuario.DTO.LoginDTO;
import auth.com.usuario.DTO.TokenDTO;
import auth.com.usuario.DTO.UsuarioCadastroDTO;
import auth.com.usuario.DTO.UsuarioExibicaoDTO;
import auth.com.usuario.Model.Usuario;
import auth.com.usuario.Service.UsuarioService;
import auth.com.usuario.Token.TokenService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("auth")
public class Usuariocontroller {

    @Autowired
    private UsuarioService usuarioService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("usuario/login")
    public ResponseEntity login(@RequestBody @Valid LoginDTO loginDTO){
        UsernamePasswordAuthenticationToken senhaUsuario = new UsernamePasswordAuthenticationToken(loginDTO.email(), loginDTO.senha());

        Authentication auth = authenticationManager.authenticate(senhaUsuario);
        String token = tokenService.gerarToken((Usuario) auth.getPrincipal());

        return ResponseEntity.ok(new TokenDTO(token));
    }

    @PostMapping("/usuario/cadastrar")
    @ResponseStatus(HttpStatus.CREATED)
    public UsuarioExibicaoDTO cadastrarUsuario(@RequestBody @Valid UsuarioCadastroDTO usuarioCadastroDTO){
        return usuarioService.cadastrarUsuario(usuarioCadastroDTO);
    }

    @GetMapping("/usuario/listarTodos")
    @ResponseStatus(HttpStatus.OK)
    public Page<UsuarioExibicaoDTO> listatTodos(Pageable pageable){
        return usuarioService.listarTodos(pageable);
    }

    @PutMapping("/usuario/atualizar")
    @ResponseStatus(HttpStatus.OK)
    public UsuarioExibicaoDTO atualizar (@RequestBody Usuario usuario){
        return usuarioService.atualizar(usuario);
    }

    @DeleteMapping("/usuario/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void excluir (@PathVariable Long id){
        usuarioService.excluir(id);
    }
}
