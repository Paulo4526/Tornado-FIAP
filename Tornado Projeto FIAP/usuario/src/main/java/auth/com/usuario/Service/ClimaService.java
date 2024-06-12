package auth.com.usuario.Service;

import auth.com.usuario.DTO.models.ClimaCadastroDTO;
import auth.com.usuario.DTO.models.ClimaExibicaoDTO;
import auth.com.usuario.Exceptions.UserNaoEncontrado;
import auth.com.usuario.Model.Clima;
import auth.com.usuario.Repository.ClimaRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ClimaService {

    @Autowired
    private ClimaRepository climaRepository;

    public ClimaExibicaoDTO cadastrar (ClimaCadastroDTO climaCadastroDTO){
        Clima clima = new Clima();
        BeanUtils.copyProperties(climaCadastroDTO, clima);

        Clima salvarClima = climaRepository.save(clima);
        return new ClimaExibicaoDTO(salvarClima);
    }


    public Page<ClimaExibicaoDTO> listarTodos (Pageable pageable){
        return climaRepository.findAll(pageable) .map(ClimaExibicaoDTO::new);
    }


    public ClimaExibicaoDTO atualizar (Clima clima){
        Optional<Clima> optionalClima = climaRepository.findById(clima.getId());
        if (optionalClima.isPresent()){
            climaRepository.save(clima);
            return new ClimaExibicaoDTO(clima);

        }else {
            throw  new UserNaoEncontrado("Clima não cadastrado");
        }
    }

    public void excluir (Long id){
        Optional<Clima> optionalClima = climaRepository.findById(id);
        if (optionalClima.isPresent()){
            climaRepository.delete(optionalClima.get());
        }else{
            throw new UserNaoEncontrado("Clima não cadastrado");
        }
    }

}
