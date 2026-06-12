# Deep Packet Inspection System

This project is a Deep Packet Inspection (DPI) System developed using **Java**, **Spring Boot**, **MySQL**, **Pcap4J**, and **Npcap**. The main objective of this project is to capture network packets, analyze them, and monitor network traffic through a web-based dashboard.

The application captures live packets from the network, extracts useful information such as **Source IP**, **Destination IP**, **Protocol**, **Port Number**, and **Domain Details**, and stores the data in a MySQL database for monitoring and analysis.

## Features

### User Authentication

- User Registration
- Email Verification using verification link
- User Login

### Packet Capture

- Live packet capture using **Pcap4J**
- Network interface detection
- TCP packet monitoring
- UDP packet monitoring
- DNS packet inspection
- Start and stop packet capture from dashboard

### Packet Analysis

- Source and Destination IP tracking
- Protocol identification
- Port analysis
- Packet size monitoring
- Domain extraction from DNS traffic
- Real-time packet monitoring

### Threat Monitoring

- Detection of suspicious packets
- Identification of dangerous domains
- Traffic monitoring based on predefined rules
- Top attacker analysis
- Threat level classification
- Suspicious traffic tracking

### Security Management

- Block suspicious IP addresses
- Block dangerous domains
- Unblock blocked entries
- Threat monitoring and validation

### Dashboard

- View captured packets
- Monitor packet statistics
- Search packets using Protocol, IP Address, or Status
- View suspicious traffic activity
- Manage blocked IPs and domains
- View top attackers
- View dangerous domains
- Monitor recent network activity

## Technology Stack

### Backend

- **Java 17**
- **Spring Boot**
- **Spring MVC**
- **Spring Data JPA**
- **Hibernate**

### Frontend

- **Thymeleaf**
- **HTML**
- **CSS**
- **JavaScript**

### Database

- **MySQL**

### Packet Capturing

- **Pcap4J**
- **Npcap**

### Additional Libraries

- **Spring Mail**
- **Jakarta Persistence API**

### Build Tool

- **Maven**

## Project Modules

### Authentication Module

- Registration
- Email Verification
- Login

### Packet Capture Module

- Live packet capture
- Protocol detection
- DNS monitoring
- Packet storage

### Threat Detection Module

- Traffic analysis
- Domain analysis
- Packet classification
- Suspicious activity detection

### Security Management Module

- IP blocking
- Domain blocking
- Unblock functionality
- Threat monitoring

### Dashboard Module

- Packet statistics
- Traffic monitoring
- Suspicious packet tracking
- Top attacker analysis
- Dangerous domain monitoring

## Threat Classification

Packets are categorized into the following levels:

- **Safe**
- **Monitor**
- **Suspicious**
- **Blocked**

The classification is based on different packet characteristics and predefined detection rules.

## Project Structure

```text
src/main/java/com/pooja/dpi
│
├── capture
│   ├── CaptureController
│   └── PacketCaptureService
│
├── controller
│   ├── AuthController
│   ├── DashboardController
│   └── PacketController
│
├── entity
│   ├── Packet
│   └── User
│
├── repository
│   ├── PacketRepository
│   └── UserRepository
│
├── service
│   ├── EmailService
│   └── UserService
│
└── DpiSystemApplication
```

## Database Entities

### User

| Field | Description |
|---------|------------|
| id | User ID |
| name | User Name |
| email | User Email |
| password | User Password |
| verified | Verification Status |
| verificationToken | Email Verification Token |

### Packet

| Field | Description |
|---------|------------|
| id | Packet ID |
| sourceIp | Source IP Address |
| destinationIp | Destination IP Address |
| protocol | TCP / UDP |
| port | Port Number |
| packetSize | Packet Size |
| timestamp | Packet Timestamp |
| status | Packet Status |
| domain | Extracted Domain |
| threatLevel | Threat Level |
| reason | Detection Reason |

## REST API Endpoints

### Packet APIs

- `GET /api/packets`
- `GET /api/packets/live`
- `GET /api/packets/suspicious`
- `GET /api/packets/stats`
- `GET /api/packets/top-attackers`
- `GET /api/packets/dangerous-domains`
- `GET /api/packets/protocol/{protocol}`
- `GET /api/packets/source/{ip}`
- `GET /api/packets/port/{port}`

### Security APIs

- `POST /api/packets/block`
- `POST /api/packets/unblock`

### Capture APIs

- `POST /api/capture/start`
- `POST /api/capture/stop`

## Prerequisites

Before running the project, make sure the following software is installed:

- Java 17 or higher
- MySQL Server
- Maven
- Npcap (Windows)

> Npcap is required because Pcap4J uses it to capture live network traffic from the system.

## Running the Project

### Clone the Repository

```bash
git clone https://github.com/PoojaGangwani48/deep-packet-inspection-system.git
```

### Move to the Project Directory

```bash
cd deep-packet-inspection-system
```

### Configure Database

Update the database configuration inside:

```properties
application.properties
```

### Run the Application

```bash
mvn spring-boot:run
```

### Open in Browser

```text
http://localhost:8082
```

## What I Learned

- Packet capturing using Pcap4J
- Basics of Deep Packet Inspection
- DNS traffic analysis
- Spring Boot application development
- Database integration using JPA and MySQL
- Email verification implementation
- REST API development
- Network monitoring concepts

## Future Enhancements

- Advanced threat detection rules
- Email alerts for suspicious traffic
- Packet export reports
- Enhanced dashboard analytics
- Role-based access control
- Advanced traffic visualization

## Developer

**Pooja Gangwani**

MCA Student | Java Full Stack Developer

GitHub: https://github.com/PoojaGangwani48

## License

This project was developed for educational and learning purposes.