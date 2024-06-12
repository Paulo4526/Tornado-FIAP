package auth.com.usuario.Repository;

import auth.com.usuario.Model.Clima;
import auth.com.usuario.Model.Tornado;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDate;
import java.util.Optional;

public interface ClimaRepository extends JpaRepository<Clima, Long> {
    public Optional<Clima> findById(Long id);
    //public Optional<Clima> findByData(LocalDate data);
}
