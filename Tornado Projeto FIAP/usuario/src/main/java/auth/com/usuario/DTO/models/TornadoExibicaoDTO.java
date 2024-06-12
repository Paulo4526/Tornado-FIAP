package auth.com.usuario.DTO.models;

import auth.com.usuario.Model.Tornado;

import java.time.LocalDate;

public record TornadoExibicaoDTO(
        Long id,
        String nome,
        String classificacao,
        String local,
        LocalDate data
) {
    public TornadoExibicaoDTO (Tornado tornado){
        this(tornado.getId(), tornado.getNome(), tornado.getClassificacao(), tornado.getLocal(), tornado.getData());
    }
}
