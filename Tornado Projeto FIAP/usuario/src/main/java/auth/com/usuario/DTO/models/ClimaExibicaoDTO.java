package auth.com.usuario.DTO.models;

import auth.com.usuario.Model.Clima;

import java.time.LocalDate;

public record ClimaExibicaoDTO(
        Long id,
        Long idTornado,
        String clima,
        Integer temperatura,
        LocalDate data,
        String local
) {
    public ClimaExibicaoDTO (Clima clima){
        this(clima.getId(), clima.getIdTornado(), clima.getClima(), clima.getTemperatura(), clima.getData(), clima.getLocal());
    }
}
