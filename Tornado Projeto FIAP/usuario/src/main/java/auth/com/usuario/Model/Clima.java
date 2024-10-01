package auth.com.usuario.Model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;

@Entity
@Table(name = "TB_MICRO_CLIMA")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Clima {


    @Id
    @GeneratedValue(generator = "SQ_MICRO_CLIMA", strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(name = "SQ_MICRO_CLIMA", sequenceName = "SQ_MICRO_CLIMA", allocationSize = 1)
    @Column(name = "id_clima")
    private Long id;

    @Column(name = "id_tornado")
    private Long idTornados;

    @Column(name = "ds_clima")
    private String clima;

    @Column(name = "vl_temperatura")
    private Integer temperatura;

    @Column(name = "data_clima")
    private LocalDate data;

    @Column(name = "ds_local")
    private String local;

}
