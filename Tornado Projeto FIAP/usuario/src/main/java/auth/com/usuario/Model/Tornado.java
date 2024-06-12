package auth.com.usuario.Model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.time.LocalDate;


@Entity
@Table(name = "TB_MICRO_TORNADO")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Tornado {
    @Id
    @GeneratedValue(generator = "SQ_MICRO_TORNADO", strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(name = "SQ_MICRO_TORNADO", sequenceName = "SQ_MICRO_TORNADO", allocationSize = 1)
    @Column(name = "id_tornado")
    private Long id;

    @Column(name = "nome_tornado")
    private String nome;

    private String classificacao;

    @Column(name = "local_origem")
    private String local;

    @Column(name = "data_origem")
    private LocalDate data;
}
