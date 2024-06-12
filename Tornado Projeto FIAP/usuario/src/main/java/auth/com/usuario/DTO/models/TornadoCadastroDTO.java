package auth.com.usuario.DTO.models;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDate;

public record TornadoCadastroDTO (
        @NotBlank(message = "O nome do tornado é obrigatório!")
        String nome,

        @NotBlank(message = "A classificação do tornado é obrigatório!")
        String classificacao,

        @NotBlank(message = "O local origem do tornado é obrigatporio!")
        String local,

        @NotNull(message = "A data não pode ser nula!")
        LocalDate data
) {

}
