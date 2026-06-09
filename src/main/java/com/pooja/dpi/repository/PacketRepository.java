package com.pooja.dpi.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.data.repository.query.Param;

import com.pooja.dpi.entity.Packet;

@Repository
public interface PacketRepository extends JpaRepository<Packet, Long> {

    List<Packet> findByStatus(String status);
    List<Packet> findByProtocol(String protocol);
    List<Packet> findBySourceIp(String sourceIp);
    List<Packet> findByPort(Integer port);
    List<Packet> findByThreatLevel(String threatLevel);

    long countByThreatLevel(String threatLevel);

    List<Packet> findTop10ByOrderByTimestampDesc();

    @Query(
        "SELECT p.sourceIp, COUNT(p) " +
        "FROM Packet p " +
        "WHERE p.threatLevel = :level " +
        "GROUP BY p.sourceIp " +
        "HAVING COUNT(p) > 5 " +
        "ORDER BY COUNT(p) DESC"
    )
    List<Object[]> findTopAttackers(@Param("level") String level);

    @Query(
        "SELECT p.domain, COUNT(p) " +
        "FROM Packet p " +
        "WHERE p.threatLevel = :level AND p.domain IS NOT NULL " +
        "GROUP BY p.domain " +
        "ORDER BY COUNT(p) DESC"
    )
    List<Object[]> findDangerousDomains(@Param("level") String level);

    @Query("SELECT COUNT(p) FROM Packet p WHERE p.timestamp >= :time")
    long countPacketsAfter(@Param("time") LocalDateTime time);
}