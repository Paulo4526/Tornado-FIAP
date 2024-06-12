package auth.com.usuario.DTO.models;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDate;

public record ClimaCadastroDTO (
        Long id,

        @NotNull(message = "Um id de tornado valido é obrigatório!")
        Long idTornado,

        @NotBlank(message = "O preenchimento do campo clima é obrigatório!")
        String clima,

        @NotNull(message = "O preenchimento do campo temperatura é obrigatório!")
        Integer temperatura,

        @NotNull(message ="O preenchimento do campo data é obrigatório!")
        LocalDate data,

        @NotBlank(message = "O campo local é obrigatório!")
        String local
){
}
