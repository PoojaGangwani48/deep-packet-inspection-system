package com.pooja.dpi.service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.pooja.dpi.entity.Packet;
import com.pooja.dpi.repository.PacketRepository;

@Service
public class PacketService {

    @Autowired
    private PacketRepository packetRepository;

    private Map<String, Integer> ipCountMap =
            new ConcurrentHashMap<>();
    private Set<String> blockedDomains =
            new HashSet<>();

    private Set<String> blockedIps =
            new HashSet<>();
    
    public String detectThreat(Packet packet) {

        if (packet == null) {
            return "Safe";
        }
        if (isBlocked(packet)) {

            packet.setReason("Blocked IP/Domain");

            return "Blocked";
        }

        String sourceIp =
                normalize(packet.getSourceIp());

        String domain =
                normalize(packet.getDomain());

        String protocol =
                packet.getProtocol();

        Integer port =
                packet.getPort();

        Integer packetSize =
                packet.getPacketSize();

        int score = 0;

        List<String> reasons =
                new ArrayList<>();

        List<String> trustedDomains =
                Arrays.asList(
                        "google.com",
                        "youtube.com",
                        "gstatic.com",
                        "googleapis.com",
                        "microsoft.com",
                        "bing.com",
                        "ytimg.com",
                        "chatgpt.com"
                );

        if (domain != null) {

            boolean trusted =
                    trustedDomains.stream()
                            .anyMatch(domain::contains);

            if (trusted) {

                packet.setReason("Trusted Safe Traffic");

                return "Safe";
            }
        }

        int count = 0;

        if (sourceIp != null) {

            count =
                    ipCountMap.getOrDefault(sourceIp, 0) + 1;

            ipCountMap.put(sourceIp, count);

            
            if (count > 30 && count <= 60) {

                score += 3;

                reasons.add(
                        "High Traffic Volume"
                );
            }

            
            else if (count > 60) {

                score += 6;

                reasons.add(
                        "Heavy Flood Traffic"
                );
            }
        }



        boolean suspiciousPort = false;

        if (port != null) {

            List<Integer> dangerousPorts =
                    Arrays.asList(
                            21,
                            23,
                            445,
                            3389,
                            4444,
                            6667
                    );

            if (dangerousPorts.contains(port)) {

                suspiciousPort = true;

                score += 4;

                reasons.add(
                        "Suspicious Port: " + port
                );
            }
        }


        if (protocol != null &&
                protocol.equalsIgnoreCase("ICMP")) {

            if (count > 20) {

                score += 5;

                reasons.add(
                        "ICMP Flood Attack"
                );
            }
        }


        if (packetSize != null &&
                packetSize > 1200) {

            score += 3;

            reasons.add(
                    "Abnormally Large Packet"
            );
        }



        if (domain != null) {

            List<String> suspiciousKeywords =
                    Arrays.asList(
                            "phishing",
                            "malware",
                            "trojan",
                            "stealer",
                            "darkweb",
                            "hack",
                            "attack",
                            "virus",
                            "spyware",
                            "ransomware",
                            "botnet"
                    );

            boolean suspiciousDomain =
                    suspiciousKeywords
                            .stream()
                            .anyMatch(domain::contains);

            if (suspiciousDomain) {

                score += 7;

                reasons.add(
                        "Suspicious Domain: " + domain
                );
            }
        }


        if (suspiciousPort && count > 20) {

            score += 3;

            reasons.add(
                    "Port + Flood Combination"
            );
        }

        if (score >= 7) {

            packet.setReason(
                    String.join(", ", reasons)
            );

            return "Suspicious";
        }

        else if (score >= 3) {

            packet.setReason(
                    String.join(", ", reasons)
            );

            return "Monitor";
        }

        else {

            packet.setReason(
                    "Safe Traffic"
            );

            return "Safe";
        }
    }


    public Packet save(Packet packet) {

        String threatLevel =
                detectThreat(packet);

        packet.setThreatLevel(threatLevel);

        packet.setStatus(threatLevel);

        return packetRepository.save(packet);
    }



    @Scheduled(fixedRate = 60000)
    public void clearIpMap() {

        System.out.println("IP Count Reset");

        ipCountMap.clear();
    }



    public List<Packet> getAllPackets() {

        return packetRepository.findAll();
    }

    public List<Packet> getSuspiciousPackets() {

        return packetRepository
                .findByThreatLevel("Suspicious");
    }

    public List<Packet> getByProtocol(String protocol) {

        return packetRepository
                .findByProtocol(protocol);
    }

    public List<Packet> getBySourceIp(String sourceIp) {

        return packetRepository
                .findBySourceIp(sourceIp);
    }

    public List<Packet> getByPort(Integer port) {

        return packetRepository
                .findByPort(port);
    }

    public List<Object[]> getTopAttackers() {

        return packetRepository
                .findTopAttackers("Suspicious");
    }

    public List<Object[]> getDangerousDomains() {

        return packetRepository
                .findDangerousDomains("Suspicious");
    }

    public List<Packet> getLivePackets() {

        return packetRepository
                .findTop10ByOrderByTimestampDesc();
    }

    public long getLastMinutePackets() {

        LocalDateTime oneMinuteAgo =
                LocalDateTime.now()
                        .minusMinutes(1);

        return packetRepository
                .countPacketsAfter(oneMinuteAgo);
    }


   public Map<String, Long> getPacketStats() {

        Map<String, Long> stats =
                new HashMap<>();

        stats.put(
                "Total",
                packetRepository.count()
        );

        stats.put(
                "Safe",
                packetRepository
                        .countByThreatLevel("Safe")
        );

        stats.put(
                "Monitor",
                packetRepository
                        .countByThreatLevel("Monitor")
        );

        stats.put(
                "Suspicious",
                packetRepository
                        .countByThreatLevel("Suspicious")
        );

        stats.put(
                "Blocked",
                packetRepository
                        .countByThreatLevel("Blocked")
        );

        return stats;
    }



      public void blockValue(String value) {

        if (value == null) {
            return;
        }

        value = normalize(value);

        if (value.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {

            blockedIps.add(value);

        } else {

            blockedDomains.add(value);
        }
    }



    public void unblockValue(String value) {

        if (value == null) {
            return;
        }

        value = normalize(value);

        blockedDomains.remove(value);

        blockedIps.remove(value);
    }



    public List<String> getBlockedDomains() {

        return new ArrayList<>(blockedDomains);
    }



    public List<String> getBlockedIps() {

        return new ArrayList<>(blockedIps);
    }



    private boolean isBlocked(Packet packet) {

        String ip =
                normalize(packet.getSourceIp());

        String domain =
                normalize(packet.getDomain());

        if (ip != null &&
                blockedIps.contains(ip)) {

            return true;
        }

        if (domain != null &&
                blockedDomains.contains(domain)) {

            return true;
        }

        return false;
    }


    private String normalize(String value) {

        if (value == null) {
            return null;
        }

        return value
                .replace("/", "")
                .replace("\\", "")
                .toLowerCase()
                .trim()
                .replaceAll(":\\d+", "");
    }
    public List<Packet> filterPackets(
            String keyword,
            String protocol,
            String status){

        List<Packet> packets = packetRepository.findAll();

        return packets.stream()

                .filter(p -> {

                    boolean matchesKeyword =
                            keyword == null ||
                            keyword.isBlank() ||

                            (p.getSourceIp() != null &&
                             p.getSourceIp()
                              .toLowerCase()
                              .contains(keyword.toLowerCase()))

                            ||

                            (p.getDestinationIp() != null &&
                             p.getDestinationIp()
                              .toLowerCase()
                              .contains(keyword.toLowerCase()))

                            ||

                            (p.getDomain() != null &&
                             p.getDomain()
                              .toLowerCase()
                              .contains(keyword.toLowerCase()));



                    boolean matchesProtocol =
                            protocol == null ||
                            protocol.isBlank() ||

                            (p.getProtocol() != null &&
                             p.getProtocol()
                              .equalsIgnoreCase(protocol));



                    boolean matchesStatus =
                            status == null ||
                            status.isBlank() ||

                            (p.getStatus() != null &&
                             p.getStatus()
                              .equalsIgnoreCase(status));



                    return matchesKeyword
                            && matchesProtocol
                            && matchesStatus;
                })

                .toList();
    }
}