package auth.com.usuario.Model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;

@Entity
@Table(name = "TB_MICRO_DANO")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Danos {

    @Id
    @GeneratedValue(generator = "SQ_MICRO_DANO", strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(name = "SQ_MICRO_DANO", sequenceName = "SQ_MICRO_DANO", allocationSize = 1)
    @Column(name = "id_dano")
    private Long id;

    @Column(name = "id_tornado")
    private Long idTornado;

    @Column(name = "ds_dano")
    private String dano;

    @Column(name = "ds_local")
    private String local;
}
