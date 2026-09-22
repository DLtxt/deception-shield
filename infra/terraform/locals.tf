locals {
  name_prefix = "${var.project_name}-${var.environment}"

  # T-Pot binds its administrative services high in the port range so that the
  # conventional ports stay free for the honeypot listeners below.
  management_ports = {
    cockpit = 64294
    ssh     = 64295
    web     = 64297
  }

  # Ports deliberately exposed to the internet. Each maps to a honeypot daemon
  # rather than a real service, so inbound traffic here is the product itself.
  honeypot_tcp_ports = [
    21,    # Dionaea FTP
    22,    # Cowrie SSH
    23,    # Cowrie Telnet
    25,    # Mailoney SMTP
    42,    # Honeytrap
    69,    # Dionaea TFTP
    80,    # Tanner HTTP
    110,   # Dionaea POP3
    135,   # Dionaea MSRPC
    143,   # Dionaea IMAP
    443,   # Tanner HTTPS
    445,   # Dionaea SMB
    1433,  # Dionaea MSSQL
    1723,  # Dionaea PPTP
    1883,  # Dionaea MQTT
    3306,  # Dionaea MySQL
    3389,  # RDPY remote desktop
    5060,  # SIP
    5432,  # Dionaea PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080,  # Tanner alternate HTTP
    9200,  # Elasticsearch decoy
    11211, # Memcached
  ]

  honeypot_udp_ports = [
    69,   # TFTP
    123,  # NTP amplification probes
    161,  # SNMP
    5060, # SIP
  ]
}
