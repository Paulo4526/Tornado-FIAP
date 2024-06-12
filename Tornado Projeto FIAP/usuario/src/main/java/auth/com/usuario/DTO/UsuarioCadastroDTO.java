package auth.com.usuario.DTO;

import auth.com.usuario.Model.UserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

public record UsuarioCadastroDTO(

        Long id,
        @NotBlank(message = "O Campo nome deve ser preenchido obrigatóriamente!")
        @Size(min = 10, message = "O nome e o sobrenome devem conter no mínimo 10 letras")
        String nome,

        @NotBlank(message = "O campo email deve ser preenchido obrigatoriamente!")
        @Email(message = "O campo email deve ser preenchido no formado eeee@eee.com")
        String email,

        @NotBlank(message = "O campo senha deves er preenchido obrigatóriamente!")
        @Size(min = 8, message = "O campo senha deve ter no mínimo 8 letras!")
        String senha,

        UserRole user,
        LocalDate data
) {
}
