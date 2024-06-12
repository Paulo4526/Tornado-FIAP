package auth.com.usuario.Controller;


import auth.com.usuario.DTO.models.TornadoCadastroDTO;
import auth.com.usuario.DTO.models.TornadoExibicaoDTO;
import auth.com.usuario.Model.Tornado;
import auth.com.usuario.Service.TornadoService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;

@RestController
@RequestMapping("tornado")
public class TornadoController {

    @Autowired
    private TornadoService tornadoService;

    @PostMapping("/cadastrar")
    @ResponseStatus(HttpStatus.CREATED)
    public TornadoExibicaoDTO cadastrar (@RequestBody @Valid TornadoCadastroDTO tornadoCadastroDTO){
        return tornadoService.cadastrar(tornadoCadastroDTO);
    }

    @PutMapping("/atualizar")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public TornadoExibicaoDTO atualizar(@RequestBody Tornado tornado){
        return tornadoService.atualizar(tornado);
    }

    @GetMapping("/listarTodos")
    @ResponseStatus(HttpStatus.OK)
    public Page<TornadoExibicaoDTO> listarTodos (Pageable pageable){return tornadoService.listarTodos(pageable);}

    @DeleteMapping("excluir/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void exluir(@PathVariable  Long id){
        tornadoService.excluir(id);
    }

    @GetMapping( value = "/buscarPorNome", params = "nome")
    @ResponseStatus(HttpStatus.OK)
    public TornadoExibicaoDTO buscarPorNome (@RequestParam String nome){
        return tornadoService.buscarNome(nome);
    }

    @GetMapping(value = "/buscarEntreData", params = {"dataInicial", "dataFinal"})
    @ResponseStatus(HttpStatus.OK)
    public List<TornadoExibicaoDTO> buscarEntreData(@RequestParam LocalDate dataInicial, @RequestParam LocalDate dataFinal){
        return tornadoService.buscarEntreData(dataInicial, dataFinal);
    }

}
