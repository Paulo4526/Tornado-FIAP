package auth.com.usuario.DTO.models;

import auth.com.usuario.Model.Danos;

public record DanoExibicaoDTO(
        Long id,
        Long idTornado,
        String dano,
        String local

) {
    public DanoExibicaoDTO (Danos danos){
        this(danos.getId(), danos.getIdTornado(), danos.getDano(), danos.getLocal());
    }
}
