package auth.com.usuario.DTO;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginDTO(
        @NotBlank(message = "O campo email deve ser preenchido obrigatoriamente!")
        @Email(message = "O campo email deve ser preenchido no formado eeee@eee.com")
        String email,

        @NotBlank(message = "O campo senha deves er preenchido obrigatóriamente!")
        @Size(min = 8, message = "O campo senha deve ter no mínimo 8 letras!")
        String senha
) {
}
