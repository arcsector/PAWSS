from typing import Any
class Blocklist:
    '''Representation of report Blocklist with type blocklist and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/blocklist-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        hostname (Any): Report attribute hostname
        source (Any): Report attribute source
        reason (Any): Report attribute reason
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        sector (Any): Report attribute sector
        tag (Any): Report attribute tag
    '''
    timestamp: Any
    severity: Any
    ip: Any
    hostname: Any
    source: Any
    reason: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    sector: Any
    tag: Any

class CompromisedAccount:
    '''Representation of report Compromised-Account with type data-leak and taxonomy information-content-security

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/compromised-account-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        email (Any): Report attribute email
        infection (Any): Report attribute infection
        source_url (Any): Report attribute source_url
        public_source (Any): Report attribute public_source
        status (Any): Report attribute status
        tag (Any): Report attribute tag
        severity (Any): Report attribute severity
        service (Any): Report attribute service
        username (Any): Report attribute username
        detail (Any): Report attribute detail
    '''
    timestamp: Any
    email: Any
    infection: Any
    source_url: Any
    public_source: Any
    status: Any
    tag: Any
    severity: Any
    service: Any
    username: Any
    detail: Any

class CompromisedWebsite:
    '''Representation of report Compromised-Website with type system-compromise and taxonomy intrusions

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/compromised-website-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        url (Any): Report attribute url
        http_host (Any): Report attribute http_host
        category (Any): Report attribute category
        system (Any): Report attribute system
        detected_since (Any): Report attribute detected_since
        server (Any): Report attribute server
        redirect_target (Any): Report attribute redirect_target
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        cc_url (Any): Report attribute cc_url
        family (Any): Report attribute family
        status (Any): Report attribute status
        account (Any): Report attribute account
        detail (Any): Report attribute detail
        public_source (Any): Report attribute public_source
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    application: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    url: Any
    http_host: Any
    category: Any
    system: Any
    detected_since: Any
    server: Any
    redirect_target: Any
    naics: Any
    hostname_source: Any
    sector: Any
    cc_url: Any
    family: Any
    status: Any
    account: Any
    detail: Any
    public_source: Any

class CompromisedWebsite6:
    '''Representation of report IPv6-Compromised-Website with type system-compromise and taxonomy intrusions

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/compromised-website-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        url (Any): Report attribute url
        http_host (Any): Report attribute http_host
        category (Any): Report attribute category
        system (Any): Report attribute system
        detected_since (Any): Report attribute detected_since
        server (Any): Report attribute server
        redirect_target (Any): Report attribute redirect_target
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        cc_url (Any): Report attribute cc_url
        family (Any): Report attribute family
        status (Any): Report attribute status
        account (Any): Report attribute account
        detail (Any): Report attribute detail
        public_source (Any): Report attribute public_source
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    application: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    url: Any
    http_host: Any
    category: Any
    system: Any
    detected_since: Any
    server: Any
    redirect_target: Any
    naics: Any
    hostname_source: Any
    sector: Any
    cc_url: Any
    family: Any
    status: Any
    account: Any
    detail: Any
    public_source: Any

class DeviceId:
    '''Representation of report Device-Identification IPv4 with type undetermined and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/device-identification-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any

class DeviceId6:
    '''Representation of report Device-Identification IPv6 with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any

class Event4DdosParticipant:
    '''Representation of report DDoS-Participant with type ddos and taxonomy availability

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/ddos-participant-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        domain_source (Any): Report attribute domain_source
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        dst_network (Any): Report attribute dst_network
        dst_netmask (Any): Report attribute dst_netmask
        attack (Any): Report attribute attack
        duration (Any): Report attribute duration
        attack_src_ip (Any): Report attribute attack_src_ip
        attack_src_port (Any): Report attribute attack_src_port
        domain (Any): Report attribute domain
        domain_transaction_id (Any): Report attribute domain_transaction_id
        gcip (Any): Report attribute gcip
        http_method (Any): Report attribute http_method
        http_path (Any): Report attribute http_path
        http_postdata (Any): Report attribute http_postdata
        http_usessl (Any): Report attribute http_usessl
        ip_header_ack (Any): Report attribute ip_header_ack
        ip_header_acknum (Any): Report attribute ip_header_acknum
        ip_header_dont_fragment (Any): Report attribute ip_header_dont_fragment
        ip_header_fin (Any): Report attribute ip_header_fin
        ip_header_identity (Any): Report attribute ip_header_identity
        ip_header_psh (Any): Report attribute ip_header_psh
        ip_header_rst (Any): Report attribute ip_header_rst
        ip_header_seqnum (Any): Report attribute ip_header_seqnum
        ip_header_syn (Any): Report attribute ip_header_syn
        ip_header_tos (Any): Report attribute ip_header_tos
        ip_header_ttl (Any): Report attribute ip_header_ttl
        ip_header_urg (Any): Report attribute ip_header_urg
        number_of_connections (Any): Report attribute number_of_connections
        packet_length (Any): Report attribute packet_length
        packet_randomized (Any): Report attribute packet_randomized
        http_agent (Any): Report attribute http_agent
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    domain_source: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    dst_network: Any
    dst_netmask: Any
    attack: Any
    duration: Any
    attack_src_ip: Any
    attack_src_port: Any
    domain: Any
    domain_transaction_id: Any
    gcip: Any
    http_method: Any
    http_path: Any
    http_postdata: Any
    http_usessl: Any
    ip_header_ack: Any
    ip_header_acknum: Any
    ip_header_dont_fragment: Any
    ip_header_fin: Any
    ip_header_identity: Any
    ip_header_psh: Any
    ip_header_rst: Any
    ip_header_seqnum: Any
    ip_header_syn: Any
    ip_header_tos: Any
    ip_header_ttl: Any
    ip_header_urg: Any
    number_of_connections: Any
    packet_length: Any
    packet_randomized: Any
    http_agent: Any

class Event4HoneypotAdbScan:
    '''Representation of report Honeypot-ADB-Scanner with type scanner and taxonomy information-gathering

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-adb-scanner-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        vulnerability_enum (Any): Report attribute vulnerability_enum
        vulnerability_id (Any): Report attribute vulnerability_id
        vulnerability_class (Any): Report attribute vulnerability_class
        vulnerability_score (Any): Report attribute vulnerability_score
        vulnerability_severity (Any): Report attribute vulnerability_severity
        vulnerability_version (Any): Report attribute vulnerability_version
        threat_framework (Any): Report attribute threat_framework
        threat_tactic_id (Any): Report attribute threat_tactic_id
        threat_technique_id (Any): Report attribute threat_technique_id
        target_vendor (Any): Report attribute target_vendor
        target_product (Any): Report attribute target_product
        target_class (Any): Report attribute target_class
        banner (Any): Report attribute banner
        commands (Any): Report attribute commands
        maxdata (Any): Report attribute maxdata
        system_type (Any): Report attribute system_type
        opened (Any): Report attribute opened
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    vulnerability_enum: Any
    vulnerability_id: Any
    vulnerability_class: Any
    vulnerability_score: Any
    vulnerability_severity: Any
    vulnerability_version: Any
    threat_framework: Any
    threat_tactic_id: Any
    threat_technique_id: Any
    target_vendor: Any
    target_product: Any
    target_class: Any
    banner: Any
    commands: Any
    maxdata: Any
    system_type: Any
    opened: Any

class Event4HoneypotBruteForce:
    '''Representation of report Honeypot-Brute-Force-Events with type brute-force and taxonomy intrusion-attempts

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-brute-force-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        service (Any): Report attribute service
        start_time (Any): Report attribute start_time
        end_time (Any): Report attribute end_time
        client_version (Any): Report attribute client_version
        username (Any): Report attribute username
        password (Any): Report attribute password
        payload_url (Any): Report attribute payload_url
        payload_md5 (Any): Report attribute payload_md5
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    service: Any
    start_time: Any
    end_time: Any
    client_version: Any
    username: Any
    password: Any
    payload_url: Any
    payload_md5: Any

class Event4HoneypotDarknet:
    '''Representation of report Honeypot-Darknet with type other and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-darknet-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        count (Any): Report attribute count
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    count: Any

class Event4HoneypotDdos:
    '''Representation of report Honeypot-DDoS with type ddos and taxonomy availability

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-ddos-events/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        domain_source (Any): Report attribute domain_source
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        dst_network (Any): Report attribute dst_network
        dst_netmask (Any): Report attribute dst_netmask
        attack (Any): Report attribute attack
        duration (Any): Report attribute duration
        attack_src_ip (Any): Report attribute attack_src_ip
        attack_src_port (Any): Report attribute attack_src_port
        domain (Any): Report attribute domain
        domain_transaction_id (Any): Report attribute domain_transaction_id
        gcip (Any): Report attribute gcip
        http_method (Any): Report attribute http_method
        http_path (Any): Report attribute http_path
        http_postdata (Any): Report attribute http_postdata
        http_usessl (Any): Report attribute http_usessl
        ip_header_ack (Any): Report attribute ip_header_ack
        ip_header_acknum (Any): Report attribute ip_header_acknum
        ip_header_dont_fragment (Any): Report attribute ip_header_dont_fragment
        ip_header_fin (Any): Report attribute ip_header_fin
        ip_header_identity (Any): Report attribute ip_header_identity
        ip_header_psh (Any): Report attribute ip_header_psh
        ip_header_rst (Any): Report attribute ip_header_rst
        ip_header_seqnum (Any): Report attribute ip_header_seqnum
        ip_header_syn (Any): Report attribute ip_header_syn
        ip_header_tos (Any): Report attribute ip_header_tos
        ip_header_ttl (Any): Report attribute ip_header_ttl
        ip_header_urg (Any): Report attribute ip_header_urg
        number_of_connections (Any): Report attribute number_of_connections
        packet_length (Any): Report attribute packet_length
        packet_randomized (Any): Report attribute packet_randomized
        http_agent (Any): Report attribute http_agent
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    domain_source: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    dst_network: Any
    dst_netmask: Any
    attack: Any
    duration: Any
    attack_src_ip: Any
    attack_src_port: Any
    domain: Any
    domain_transaction_id: Any
    gcip: Any
    http_method: Any
    http_path: Any
    http_postdata: Any
    http_usessl: Any
    ip_header_ack: Any
    ip_header_acknum: Any
    ip_header_dont_fragment: Any
    ip_header_fin: Any
    ip_header_identity: Any
    ip_header_psh: Any
    ip_header_rst: Any
    ip_header_seqnum: Any
    ip_header_syn: Any
    ip_header_tos: Any
    ip_header_ttl: Any
    ip_header_urg: Any
    number_of_connections: Any
    packet_length: Any
    packet_randomized: Any
    http_agent: Any

class Event4HoneypotDdosAmp:
    '''Representation of report Honeypot-Amplification-DDoS-Events with type ddos and taxonomy availability

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-amplification-ddos-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        request (Any): Report attribute request
        count (Any): Report attribute count
        bytes (Any): Report attribute bytes
        end_time (Any): Report attribute end_time
        duration (Any): Report attribute duration
        avg_pps (Any): Report attribute avg_pps
        max_pps (Any): Report attribute max_pps
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    request: Any
    count: Any
    bytes: Any
    end_time: Any
    duration: Any
    avg_pps: Any
    max_pps: Any

class Event4HoneypotDdosTarget:
    '''Representation of report Honeypot-DDoS-Target with type ddos and taxonomy availability

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-ddos-target-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        domain_source (Any): Report attribute domain_source
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        dst_network (Any): Report attribute dst_network
        dst_netmask (Any): Report attribute dst_netmask
        attack (Any): Report attribute attack
        duration (Any): Report attribute duration
        attack_src_ip (Any): Report attribute attack_src_ip
        attack_src_port (Any): Report attribute attack_src_port
        domain (Any): Report attribute domain
        domain_transaction_id (Any): Report attribute domain_transaction_id
        gcip (Any): Report attribute gcip
        http_method (Any): Report attribute http_method
        http_path (Any): Report attribute http_path
        http_postdata (Any): Report attribute http_postdata
        http_usessl (Any): Report attribute http_usessl
        ip_header_ack (Any): Report attribute ip_header_ack
        ip_header_acknum (Any): Report attribute ip_header_acknum
        ip_header_dont_fragment (Any): Report attribute ip_header_dont_fragment
        ip_header_fin (Any): Report attribute ip_header_fin
        ip_header_identity (Any): Report attribute ip_header_identity
        ip_header_psh (Any): Report attribute ip_header_psh
        ip_header_rst (Any): Report attribute ip_header_rst
        ip_header_seqnum (Any): Report attribute ip_header_seqnum
        ip_header_syn (Any): Report attribute ip_header_syn
        ip_header_tos (Any): Report attribute ip_header_tos
        ip_header_ttl (Any): Report attribute ip_header_ttl
        ip_header_urg (Any): Report attribute ip_header_urg
        number_of_connections (Any): Report attribute number_of_connections
        packet_length (Any): Report attribute packet_length
        packet_randomized (Any): Report attribute packet_randomized
    '''
    timestamp: Any
    protocol: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    domain_source: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    dst_network: Any
    dst_netmask: Any
    attack: Any
    duration: Any
    attack_src_ip: Any
    attack_src_port: Any
    domain: Any
    domain_transaction_id: Any
    gcip: Any
    http_method: Any
    http_path: Any
    http_postdata: Any
    http_usessl: Any
    ip_header_ack: Any
    ip_header_acknum: Any
    ip_header_dont_fragment: Any
    ip_header_fin: Any
    ip_header_identity: Any
    ip_header_psh: Any
    ip_header_rst: Any
    ip_header_seqnum: Any
    ip_header_syn: Any
    ip_header_tos: Any
    ip_header_ttl: Any
    ip_header_urg: Any
    number_of_connections: Any
    packet_length: Any
    packet_randomized: Any

class Event4HoneypotHttpScan:
    '''Representation of report Honeypot-HTTP-Scan with type scanner and taxonomy information-gathering

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-http-scanner-events/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        pattern (Any): Report attribute pattern
        http_url (Any): Report attribute http_url
        http_agent (Any): Report attribute http_agent
        http_request_method (Any): Report attribute http_request_method
        url_scheme (Any): Report attribute url_scheme
        session_tags (Any): Report attribute session_tags
        vulnerability_enum (Any): Report attribute vulnerability_enum
        vulnerability_id (Any): Report attribute vulnerability_id
        vulnerability_class (Any): Report attribute vulnerability_class
        vulnerability_score (Any): Report attribute vulnerability_score
        vulnerability_severity (Any): Report attribute vulnerability_severity
        vulnerability_version (Any): Report attribute vulnerability_version
        threat_framework (Any): Report attribute threat_framework
        threat_tactic_id (Any): Report attribute threat_tactic_id
        threat_technique_id (Any): Report attribute threat_technique_id
        target_vendor (Any): Report attribute target_vendor
        target_product (Any): Report attribute target_product
        target_class (Any): Report attribute target_class
        file_md5 (Any): Report attribute file_md5
        file_sha256 (Any): Report attribute file_sha256
        request_raw (Any): Report attribute request_raw
        body_raw (Any): Report attribute body_raw
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    pattern: Any
    http_url: Any
    http_agent: Any
    http_request_method: Any
    url_scheme: Any
    session_tags: Any
    vulnerability_enum: Any
    vulnerability_id: Any
    vulnerability_class: Any
    vulnerability_score: Any
    vulnerability_severity: Any
    vulnerability_version: Any
    threat_framework: Any
    threat_tactic_id: Any
    threat_technique_id: Any
    target_vendor: Any
    target_product: Any
    target_class: Any
    file_md5: Any
    file_sha256: Any
    request_raw: Any
    body_raw: Any

class Event4HoneypotIcsScan:
    '''Representation of report Honeypot-ICS-Scanner with type scanner and taxonomy information-gathering

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-ics-scanner-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        state (Any): Report attribute state
        sensor_id (Any): Report attribute sensor_id
        slave_id (Any): Report attribute slave_id
        function_code (Any): Report attribute function_code
        request (Any): Report attribute request
        response (Any): Report attribute response
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    state: Any
    sensor_id: Any
    slave_id: Any
    function_code: Any
    request: Any
    response: Any

class Event4HoneypotIkev2Scan:
    '''Representation of report Honeypot-IKEv2-Scanner with type scanner and taxonomy information-gathering

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-ikev2-scanner-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        vulnerability_enum (Any): Report attribute vulnerability_enum
        vulnerability_id (Any): Report attribute vulnerability_id
        vulnerability_class (Any): Report attribute vulnerability_class
        vulnerability_score (Any): Report attribute vulnerability_score
        vulnerability_severity (Any): Report attribute vulnerability_severity
        vulnerability_version (Any): Report attribute vulnerability_version
        threat_framework (Any): Report attribute threat_framework
        threat_tactic_id (Any): Report attribute threat_tactic_id
        threat_technique_id (Any): Report attribute threat_technique_id
        target_vendor (Any): Report attribute target_vendor
        target_product (Any): Report attribute target_product
        target_class (Any): Report attribute target_class
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    vulnerability_enum: Any
    vulnerability_id: Any
    vulnerability_class: Any
    vulnerability_score: Any
    vulnerability_severity: Any
    vulnerability_version: Any
    threat_framework: Any
    threat_tactic_id: Any
    threat_technique_id: Any
    target_vendor: Any
    target_product: Any
    target_class: Any

class Event4HoneypotRdpScan:
    '''Representation of report Honeypot-RDP-Scanner with type scanner and taxonomy information-gathering

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-rdp-scanner-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        vulnerability_enum (Any): Report attribute vulnerability_enum
        vulnerability_id (Any): Report attribute vulnerability_id
        vulnerability_class (Any): Report attribute vulnerability_class
        vulnerability_score (Any): Report attribute vulnerability_score
        vulnerability_severity (Any): Report attribute vulnerability_severity
        vulnerability_version (Any): Report attribute vulnerability_version
        threat_framework (Any): Report attribute threat_framework
        threat_tactic_id (Any): Report attribute threat_tactic_id
        threat_technique_id (Any): Report attribute threat_technique_id
        target_vendor (Any): Report attribute target_vendor
        target_product (Any): Report attribute target_product
        target_class (Any): Report attribute target_class
        cookie (Any): Report attribute cookie
        session_tags (Any): Report attribute session_tags
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    vulnerability_enum: Any
    vulnerability_id: Any
    vulnerability_class: Any
    vulnerability_score: Any
    vulnerability_severity: Any
    vulnerability_version: Any
    threat_framework: Any
    threat_tactic_id: Any
    threat_technique_id: Any
    target_vendor: Any
    target_product: Any
    target_class: Any
    cookie: Any
    session_tags: Any

class Event4HoneypotRocketmqScan:
    '''Representation of report Honeypot-RocketMQ-Scanner with type scanner and taxonomy information-gathering

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-rocketmq-scanner-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        vulnerability_enum (Any): Report attribute vulnerability_enum
        vulnerability_id (Any): Report attribute vulnerability_id
        vulnerability_class (Any): Report attribute vulnerability_class
        vulnerability_score (Any): Report attribute vulnerability_score
        vulnerability_severity (Any): Report attribute vulnerability_severity
        vulnerability_version (Any): Report attribute vulnerability_version
        threat_framework (Any): Report attribute threat_framework
        threat_tactic_id (Any): Report attribute threat_tactic_id
        threat_technique_id (Any): Report attribute threat_technique_id
        target_vendor (Any): Report attribute target_vendor
        target_product (Any): Report attribute target_product
        target_class (Any): Report attribute target_class
        code (Any): Report attribute code
        flag (Any): Report attribute flag
        language (Any): Report attribute language
        opaque (Any): Report attribute opaque
        serialize_type (Any): Report attribute serialize_type
        body (Any): Report attribute body
        body_base64 (Any): Report attribute body_base64
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    vulnerability_enum: Any
    vulnerability_id: Any
    vulnerability_class: Any
    vulnerability_score: Any
    vulnerability_severity: Any
    vulnerability_version: Any
    threat_framework: Any
    threat_tactic_id: Any
    threat_technique_id: Any
    target_vendor: Any
    target_product: Any
    target_class: Any
    code: Any
    flag: Any
    language: Any
    opaque: Any
    serialize_type: Any
    body: Any
    body_base64: Any

class Event4HoneypotSmbScan:
    '''Representation of report Honeypot-SMB-Scanner with type scanner and taxonomy information-gathering

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/honeypot-smb-scanner-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        vulnerability_enum (Any): Report attribute vulnerability_enum
        vulnerability_id (Any): Report attribute vulnerability_id
        vulnerability_class (Any): Report attribute vulnerability_class
        vulnerability_score (Any): Report attribute vulnerability_score
        vulnerability_severity (Any): Report attribute vulnerability_severity
        vulnerability_version (Any): Report attribute vulnerability_version
        threat_framework (Any): Report attribute threat_framework
        threat_tactic_id (Any): Report attribute threat_tactic_id
        threat_technique_id (Any): Report attribute threat_technique_id
        target_vendor (Any): Report attribute target_vendor
        target_product (Any): Report attribute target_product
        target_class (Any): Report attribute target_class
        command (Any): Report attribute command
        flags (Any): Report attribute flags
        supported_protocols (Any): Report attribute supported_protocols
        session_tags (Any): Report attribute session_tags
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    vulnerability_enum: Any
    vulnerability_id: Any
    vulnerability_class: Any
    vulnerability_score: Any
    vulnerability_severity: Any
    vulnerability_version: Any
    threat_framework: Any
    threat_tactic_id: Any
    threat_technique_id: Any
    target_vendor: Any
    target_product: Any
    target_class: Any
    command: Any
    flags: Any
    supported_protocols: Any
    session_tags: Any

class Event4IpSpoofer:
    '''Representation of report IP-Spoofer-Events with type masquerade and taxonomy fraud

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/ip-spoofer-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        network (Any): Report attribute network
        routedspoof (Any): Report attribute routedspoof
        session (Any): Report attribute session
        nat (Any): Report attribute nat
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    network: Any
    routedspoof: Any
    session: Any
    nat: Any

class Event4MicrosoftSinkhole:
    '''Representation of report Microsoft-Sinkhole-Events IPv4 with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        ssl_cipher (Any): Report attribute ssl_cipher
        ssl_servername (Any): Report attribute ssl_servername
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    ssl_cipher: Any
    ssl_servername: Any

class Event4MicrosoftSinkholeHttp:
    '''Representation of report Microsoft-Sinkhole-Events-HTTP IPv4 with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        http_url (Any): Report attribute http_url
        http_host (Any): Report attribute http_host
        http_agent (Any): Report attribute http_agent
        forwarded_by (Any): Report attribute forwarded_by
        ssl_cipher (Any): Report attribute ssl_cipher
        http_referer (Any): Report attribute http_referer
        ssl_servername (Any): Report attribute ssl_servername
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    http_url: Any
    http_host: Any
    http_agent: Any
    forwarded_by: Any
    ssl_cipher: Any
    http_referer: Any
    ssl_servername: Any

class Event4Sinkhole:
    '''Representation of report Sinkhole-Events IPv4 with type infected-system and taxonomy malicious-code

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/sinkhole-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        ssl_cipher (Any): Report attribute ssl_cipher
        ssl_servername (Any): Report attribute ssl_servername
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    ssl_cipher: Any
    ssl_servername: Any

class Event4SinkholeDns:
    '''Representation of report Sinkhole-DNS with type other and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/sinkhole-dns-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        query_type (Any): Report attribute query_type
        query (Any): Report attribute query
        count (Any): Report attribute count
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    infection: Any
    family: Any
    tag: Any
    query_type: Any
    query: Any
    count: Any

class Event4SinkholeHttp:
    '''Representation of report Sinkhole-Events-HTTP IPv4 with type infected-system and taxonomy malicious-code

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/sinkhole-http-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        http_url (Any): Report attribute http_url
        http_host (Any): Report attribute http_host
        http_agent (Any): Report attribute http_agent
        forwarded_by (Any): Report attribute forwarded_by
        ssl_cipher (Any): Report attribute ssl_cipher
        http_referer (Any): Report attribute http_referer
        ssl_servername (Any): Report attribute ssl_servername
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    http_url: Any
    http_host: Any
    http_agent: Any
    forwarded_by: Any
    ssl_cipher: Any
    http_referer: Any
    ssl_servername: Any

class Event4SinkholeHttpReferer:
    '''Representation of report Sinkhole-Events-HTTP-Referer IPv4 with type infected-system and taxonomy malicious-code

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/sinkhole-http-referer-events-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        http_referer_ip (Any): Report attribute http_referer_ip
        http_referer_port (Any): Report attribute http_referer_port
        http_referer_asn (Any): Report attribute http_referer_asn
        http_referer_geo (Any): Report attribute http_referer_geo
        http_referer_region (Any): Report attribute http_referer_region
        http_referer_city (Any): Report attribute http_referer_city
        http_referer_hostname (Any): Report attribute http_referer_hostname
        http_referer_naics (Any): Report attribute http_referer_naics
        http_referer_sector (Any): Report attribute http_referer_sector
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        http_url (Any): Report attribute http_url
        http_host (Any): Report attribute http_host
        http_referer (Any): Report attribute http_referer
        ssl_servername (Any): Report attribute ssl_servername
    '''
    timestamp: Any
    protocol: Any
    http_referer_ip: Any
    http_referer_port: Any
    http_referer_asn: Any
    http_referer_geo: Any
    http_referer_region: Any
    http_referer_city: Any
    http_referer_hostname: Any
    http_referer_naics: Any
    http_referer_sector: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    http_url: Any
    http_host: Any
    http_referer: Any
    ssl_servername: Any

class Event6Sinkhole:
    '''Representation of report Sinkhole-Events IPv6 with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        ssl_cipher (Any): Report attribute ssl_cipher
        ssl_servername (Any): Report attribute ssl_servername
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    ssl_cipher: Any
    ssl_servername: Any

class Event6SinkholeHttp:
    '''Representation of report Sinkhole-Events-HTTP IPv6 with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        src_ip (Any): Report attribute src_ip
        src_port (Any): Report attribute src_port
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_hostname (Any): Report attribute src_hostname
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        http_url (Any): Report attribute http_url
        http_host (Any): Report attribute http_host
        http_agent (Any): Report attribute http_agent
        forwarded_by (Any): Report attribute forwarded_by
        ssl_cipher (Any): Report attribute ssl_cipher
        http_referer (Any): Report attribute http_referer
        ssl_servername (Any): Report attribute ssl_servername
    '''
    timestamp: Any
    protocol: Any
    src_ip: Any
    src_port: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_hostname: Any
    src_naics: Any
    src_sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    http_url: Any
    http_host: Any
    http_agent: Any
    forwarded_by: Any
    ssl_cipher: Any
    http_referer: Any
    ssl_servername: Any

class Event6SinkholeHttpReferer:
    '''Representation of report Sinkhole-Events-HTTP-Referer IPv6 with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        protocol (Any): Report attribute protocol
        http_referer_ip (Any): Report attribute http_referer_ip
        http_referer_port (Any): Report attribute http_referer_port
        http_referer_asn (Any): Report attribute http_referer_asn
        http_referer_geo (Any): Report attribute http_referer_geo
        http_referer_region (Any): Report attribute http_referer_region
        http_referer_city (Any): Report attribute http_referer_city
        http_referer_hostname (Any): Report attribute http_referer_hostname
        http_referer_naics (Any): Report attribute http_referer_naics
        http_referer_sector (Any): Report attribute http_referer_sector
        severity (Any): Report attribute severity
        dst_ip (Any): Report attribute dst_ip
        dst_port (Any): Report attribute dst_port
        dst_asn (Any): Report attribute dst_asn
        dst_geo (Any): Report attribute dst_geo
        dst_region (Any): Report attribute dst_region
        dst_city (Any): Report attribute dst_city
        dst_hostname (Any): Report attribute dst_hostname
        dst_naics (Any): Report attribute dst_naics
        dst_sector (Any): Report attribute dst_sector
        public_source (Any): Report attribute public_source
        infection (Any): Report attribute infection
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        application (Any): Report attribute application
        version (Any): Report attribute version
        event_id (Any): Report attribute event_id
        http_url (Any): Report attribute http_url
        http_host (Any): Report attribute http_host
        http_referer (Any): Report attribute http_referer
        ssl_servername (Any): Report attribute ssl_servername
    '''
    timestamp: Any
    protocol: Any
    http_referer_ip: Any
    http_referer_port: Any
    http_referer_asn: Any
    http_referer_geo: Any
    http_referer_region: Any
    http_referer_city: Any
    http_referer_hostname: Any
    http_referer_naics: Any
    http_referer_sector: Any
    severity: Any
    dst_ip: Any
    dst_port: Any
    dst_asn: Any
    dst_geo: Any
    dst_region: Any
    dst_city: Any
    dst_hostname: Any
    dst_naics: Any
    dst_sector: Any
    public_source: Any
    infection: Any
    family: Any
    tag: Any
    application: Any
    version: Any
    event_id: Any
    http_url: Any
    http_host: Any
    http_referer: Any
    ssl_servername: Any

class MalwareUrl:
    '''Representation of report Malware-URL with type malware-distribution and taxonomy malicious-code

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/malware-url-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        url (Any): Report attribute url
        hostname (Any): Report attribute hostname
        ip (Any): Report attribute ip
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        sector (Any): Report attribute sector
        severity (Any): Report attribute severity
        port (Any): Report attribute port
        tag (Any): Report attribute tag
        source (Any): Report attribute source
        sha256 (Any): Report attribute sha256
        application (Any): Report attribute application
    '''
    timestamp: Any
    url: Any
    hostname: Any
    ip: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    sector: Any
    severity: Any
    port: Any
    tag: Any
    source: Any
    sha256: Any
    application: Any

class PhishUrl:
    '''Representation of report Phish-URL with type phishing and taxonomy fraud

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        url (Any): Report attribute url
        hostname (Any): Report attribute hostname
        ip (Any): Report attribute ip
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        sector (Any): Report attribute sector
        severity (Any): Report attribute severity
        port (Any): Report attribute port
        tag (Any): Report attribute tag
        source (Any): Report attribute source
    '''
    timestamp: Any
    url: Any
    hostname: Any
    ip: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    sector: Any
    severity: Any
    port: Any
    tag: Any
    source: Any

class Population6Bgp:
    '''Representation of report IPv6-Accessible-BGP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        message_length (Any): Report attribute message_length
        message_type (Any): Report attribute message_type
        message_type_int (Any): Report attribute message_type_int
        bgp_version (Any): Report attribute bgp_version
        sender_asn (Any): Report attribute sender_asn
        hold_time (Any): Report attribute hold_time
        bgp_identifier (Any): Report attribute bgp_identifier
        message2_type (Any): Report attribute message2_type
        message2_type_int (Any): Report attribute message2_type_int
        major_error_code (Any): Report attribute major_error_code
        major_error_code_int (Any): Report attribute major_error_code_int
        minor_error_code (Any): Report attribute minor_error_code
        minor_error_code_int (Any): Report attribute minor_error_code_int
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    message_length: Any
    message_type: Any
    message_type_int: Any
    bgp_version: Any
    sender_asn: Any
    hold_time: Any
    bgp_identifier: Any
    message2_type: Any
    message2_type_int: Any
    major_error_code: Any
    major_error_code_int: Any
    minor_error_code: Any
    minor_error_code_int: Any

class Population6HttpProxy:
    '''Representation of report IPv6-Accessible-HTTP-Proxy with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        sector (Any): Report attribute sector
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        connection (Any): Report attribute connection
        proxy_authenticate (Any): Report attribute proxy_authenticate
        via (Any): Report attribute via
        server (Any): Report attribute server
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    sector: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    connection: Any
    proxy_authenticate: Any
    via: Any
    server: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any

class Population6Msmq:
    '''Representation of report IPv6-Accessible-MSMQ with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    response_size: Any

class PopulationBgp:
    '''Representation of report Accessible-BGP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-bgp-service-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        message_length (Any): Report attribute message_length
        message_type (Any): Report attribute message_type
        message_type_int (Any): Report attribute message_type_int
        bgp_version (Any): Report attribute bgp_version
        sender_asn (Any): Report attribute sender_asn
        hold_time (Any): Report attribute hold_time
        bgp_identifier (Any): Report attribute bgp_identifier
        message2_type (Any): Report attribute message2_type
        message2_type_int (Any): Report attribute message2_type_int
        major_error_code (Any): Report attribute major_error_code
        major_error_code_int (Any): Report attribute major_error_code_int
        minor_error_code (Any): Report attribute minor_error_code
        minor_error_code_int (Any): Report attribute minor_error_code_int
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    message_length: Any
    message_type: Any
    message_type_int: Any
    bgp_version: Any
    sender_asn: Any
    hold_time: Any
    bgp_identifier: Any
    message2_type: Any
    message2_type_int: Any
    major_error_code: Any
    major_error_code_int: Any
    minor_error_code: Any
    minor_error_code_int: Any

class PopulationHttpProxy:
    '''Representation of report Accessible-HTTP-Proxy with type other and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-http-proxy-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        sector (Any): Report attribute sector
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        connection (Any): Report attribute connection
        proxy_authenticate (Any): Report attribute proxy_authenticate
        via (Any): Report attribute via
        server (Any): Report attribute server
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    sector: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    connection: Any
    proxy_authenticate: Any
    via: Any
    server: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any

class PopulationMsmq:
    '''Representation of report Accessible-MSMQ with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-msmq-service-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    response_size: Any

class RansomwareVictim:
    '''Representation of report Ransomware-victim with type system-compromise and taxonomy intrusions

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/ransomware-victim-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        entity_name (Any): Report attribute entity_name
        website (Any): Report attribute website
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        sector (Any): Report attribute sector
        date_published (Any): Report attribute date_published
        ransomware (Any): Report attribute ransomware
        leak_site_url (Any): Report attribute leak_site_url
        severity (Any): Report attribute severity
        actor_geo_stats_30d (Any): Report attribute actor_geo_stats_30d
        actor_total_stats_30d (Any): Report attribute actor_total_stats_30d
    '''
    timestamp: Any
    entity_name: Any
    website: Any
    geo: Any
    region: Any
    sector: Any
    date_published: Any
    ransomware: Any
    leak_site_url: Any
    severity: Any
    actor_geo_stats_30d: Any
    actor_total_stats_30d: Any

class SandboxConn:
    '''Representation of report Sandbox-Connections with type malware-distribution and taxonomy malicious-code

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/sandbox-connection-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        md5 (Any): Report attribute md5
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        bytes_in (Any): Report attribute bytes_in
        bytes_out (Any): Report attribute bytes_out
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        sector (Any): Report attribute sector
        sha1 (Any): Report attribute sha1
        sha256 (Any): Report attribute sha256
    '''
    timestamp: Any
    severity: Any
    ip: Any
    asn: Any
    geo: Any
    md5: Any
    protocol: Any
    port: Any
    hostname: Any
    bytes_in: Any
    bytes_out: Any
    region: Any
    city: Any
    naics: Any
    sector: Any
    sha1: Any
    sha256: Any

class SandboxDns:
    '''Representation of report Sandbox-DNS with type other and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        md5 (Any): Report attribute md5
        request (Any): Report attribute request
        request_type (Any): Report attribute request_type
        response (Any): Report attribute response
        family (Any): Report attribute family
        tag (Any): Report attribute tag
        source (Any): Report attribute source
        severity (Any): Report attribute severity
        sha1 (Any): Report attribute sha1
        sha256 (Any): Report attribute sha256
    '''
    timestamp: Any
    md5: Any
    request: Any
    request_type: Any
    response: Any
    family: Any
    tag: Any
    source: Any
    severity: Any
    sha1: Any
    sha256: Any

class SandboxUrl:
    '''Representation of report Sandbox-URL with type malware-distribution and taxonomy malicious-code

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/sandbox-url-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        md5 (Any): Report attribute md5
        url (Any): Report attribute url
        user_agent (Any): Report attribute user_agent
        hostname (Any): Report attribute hostname
        method (Any): Report attribute method
        naics (Any): Report attribute naics
        sector (Any): Report attribute sector
        region (Any): Report attribute region
        city (Any): Report attribute city
        port (Any): Report attribute port
        sha1 (Any): Report attribute sha1
        sha256 (Any): Report attribute sha256
    '''
    timestamp: Any
    severity: Any
    ip: Any
    asn: Any
    geo: Any
    md5: Any
    url: Any
    user_agent: Any
    hostname: Any
    method: Any
    naics: Any
    sector: Any
    region: Any
    city: Any
    port: Any
    sha1: Any
    sha256: Any

class Scan6Activemq:
    '''Representation of report IPv6-Accessible-ActiveMQ with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        command (Any): Report attribute command
        vendor (Any): Report attribute vendor
        version (Any): Report attribute version
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    command: Any
    vendor: Any
    version: Any

class Scan6Bgp:
    '''Representation of report IPv6-Open-BGP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        message_length (Any): Report attribute message_length
        message_type (Any): Report attribute message_type
        message_type_int (Any): Report attribute message_type_int
        bgp_version (Any): Report attribute bgp_version
        sender_asn (Any): Report attribute sender_asn
        hold_time (Any): Report attribute hold_time
        bgp_identifier (Any): Report attribute bgp_identifier
        message2_type (Any): Report attribute message2_type
        message2_type_int (Any): Report attribute message2_type_int
        major_error_code (Any): Report attribute major_error_code
        major_error_code_int (Any): Report attribute major_error_code_int
        minor_error_code (Any): Report attribute minor_error_code
        minor_error_code_int (Any): Report attribute minor_error_code_int
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    message_length: Any
    message_type: Any
    message_type_int: Any
    bgp_version: Any
    sender_asn: Any
    hold_time: Any
    bgp_identifier: Any
    message2_type: Any
    message2_type_int: Any
    major_error_code: Any
    major_error_code_int: Any
    minor_error_code: Any
    minor_error_code_int: Any

class Scan6Cwmp:
    '''Representation of report IPv6-Accessible-CWMP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        connection (Any): Report attribute connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server (Any): Report attribute server
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        date (Any): Report attribute date
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    connection: Any
    www_authenticate: Any
    set_cookie: Any
    server: Any
    content_length: Any
    transfer_encoding: Any
    date: Any
    sector: Any

class Scan6Dns:
    '''Representation of report IPv6-DNS-Open-Resolvers with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        dns_version (Any): Report attribute dns_version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        min_amplification (Any): Report attribute min_amplification
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    dns_version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    min_amplification: Any
    naics: Any
    hostname_source: Any
    sector: Any

class Scan6Elasticsearch:
    '''Representation of report IPv6-Open-Elasticsearch with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        ok (Any): Report attribute ok
        name (Any): Report attribute name
        cluster_name (Any): Report attribute cluster_name
        http_code (Any): Report attribute http_code
        build_hash (Any): Report attribute build_hash
        build_timestamp (Any): Report attribute build_timestamp
        build_snapshot (Any): Report attribute build_snapshot
        lucene_version (Any): Report attribute lucene_version
        tagline (Any): Report attribute tagline
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    ok: Any
    name: Any
    cluster_name: Any
    http_code: Any
    build_hash: Any
    build_timestamp: Any
    build_snapshot: Any
    lucene_version: Any
    tagline: Any
    sector: Any

class Scan6Exchange:
    '''Representation of report IPv6-Vulnerable-Exchange with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        version (Any): Report attribute version
        servername (Any): Report attribute servername
        url (Any): Report attribute url
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    version: Any
    servername: Any
    url: Any

class Scan6Ftp:
    '''Representation of report IPv6-Accessible-FTP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        banner (Any): Report attribute banner
        handshake (Any): Report attribute handshake
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        validation_level (Any): Report attribute validation_level
        auth_tls_response (Any): Report attribute auth_tls_response
        auth_ssl_response (Any): Report attribute auth_ssl_response
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        jarm (Any): Report attribute jarm
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    banner: Any
    handshake: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    validation_level: Any
    auth_tls_response: Any
    auth_ssl_response: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    jarm: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any

class Scan6Http:
    '''Representation of report IPv6-Accessible-HTTP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        sector (Any): Report attribute sector
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        connection (Any): Report attribute connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server (Any): Report attribute server
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    sector: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    connection: Any
    www_authenticate: Any
    set_cookie: Any
    server: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any

class Scan6HttpProxy:
    '''Representation of report IPv6-Open-HTTP-Proxy with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        sector (Any): Report attribute sector
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        connection (Any): Report attribute connection
        proxy_authenticate (Any): Report attribute proxy_authenticate
        via (Any): Report attribute via
        server (Any): Report attribute server
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    sector: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    connection: Any
    proxy_authenticate: Any
    via: Any
    server: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any

class Scan6HttpVulnerable:
    '''Representation of report IPv6-Vulnerable-HTTP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        sector (Any): Report attribute sector
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        connection (Any): Report attribute connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server (Any): Report attribute server
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
        version (Any): Report attribute version
        build_date (Any): Report attribute build_date
        detail (Any): Report attribute detail
        build_branch (Any): Report attribute build_branch
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    sector: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    connection: Any
    www_authenticate: Any
    set_cookie: Any
    server: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any
    version: Any
    build_date: Any
    detail: Any
    build_branch: Any

class Scan6Ipp:
    '''Representation of report IPv6-Open-IPP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        ipp_version (Any): Report attribute ipp_version
        cups_version (Any): Report attribute cups_version
        printer_uris (Any): Report attribute printer_uris
        printer_name (Any): Report attribute printer_name
        printer_info (Any): Report attribute printer_info
        printer_more_info (Any): Report attribute printer_more_info
        printer_make_and_model (Any): Report attribute printer_make_and_model
        printer_firmware_name (Any): Report attribute printer_firmware_name
        printer_firmware_string_version (Any): Report attribute printer_firmware_string_version
        printer_firmware_version (Any): Report attribute printer_firmware_version
        printer_organization (Any): Report attribute printer_organization
        printer_organization_unit (Any): Report attribute printer_organization_unit
        printer_uuid (Any): Report attribute printer_uuid
        printer_wifi_ssid (Any): Report attribute printer_wifi_ssid
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    ipp_version: Any
    cups_version: Any
    printer_uris: Any
    printer_name: Any
    printer_info: Any
    printer_more_info: Any
    printer_make_and_model: Any
    printer_firmware_name: Any
    printer_firmware_string_version: Any
    printer_firmware_version: Any
    printer_organization: Any
    printer_organization_unit: Any
    printer_uuid: Any
    printer_wifi_ssid: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any
    sector: Any

class Scan6Isakmp:
    '''Representation of report IPv6-Vulnerable-ISAKMP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        initiator_spi (Any): Report attribute initiator_spi
        responder_spi (Any): Report attribute responder_spi
        next_payload (Any): Report attribute next_payload
        exchange_type (Any): Report attribute exchange_type
        flags (Any): Report attribute flags
        message_id (Any): Report attribute message_id
        next_payload2 (Any): Report attribute next_payload2
        domain_of_interpretation (Any): Report attribute domain_of_interpretation
        protocol_id (Any): Report attribute protocol_id
        spi_size (Any): Report attribute spi_size
        notify_message_type (Any): Report attribute notify_message_type
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    initiator_spi: Any
    responder_spi: Any
    next_payload: Any
    exchange_type: Any
    flags: Any
    message_id: Any
    next_payload2: Any
    domain_of_interpretation: Any
    protocol_id: Any
    spi_size: Any
    notify_message_type: Any
    sector: Any

class Scan6LdapTcp:
    '''Representation of report IPv6-Open-LDAP-TCP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        response_size (Any): Report attribute response_size
        configuration_naming_context (Any): Report attribute configuration_naming_context
        current_time (Any): Report attribute current_time
        default_naming_context (Any): Report attribute default_naming_context
        dns_host_name (Any): Report attribute dns_host_name
        domain_controller_functionality (Any): Report attribute domain_controller_functionality
        domain_functionality (Any): Report attribute domain_functionality
        ds_service_name (Any): Report attribute ds_service_name
        forest_functionality (Any): Report attribute forest_functionality
        highest_committed_usn (Any): Report attribute highest_committed_usn
        is_global_catalog_ready (Any): Report attribute is_global_catalog_ready
        is_synchronized (Any): Report attribute is_synchronized
        ldap_service_name (Any): Report attribute ldap_service_name
        naming_contexts (Any): Report attribute naming_contexts
        root_domain_naming_context (Any): Report attribute root_domain_naming_context
        schema_naming_context (Any): Report attribute schema_naming_context
        server_name (Any): Report attribute server_name
        subschema_subentry (Any): Report attribute subschema_subentry
        supported_capabilities (Any): Report attribute supported_capabilities
        supported_control (Any): Report attribute supported_control
        supported_ldap_policies (Any): Report attribute supported_ldap_policies
        supported_ldap_version (Any): Report attribute supported_ldap_version
        supported_sasl_mechanisms (Any): Report attribute supported_sasl_mechanisms
        amplification (Any): Report attribute amplification
        handshake (Any): Report attribute handshake
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sector (Any): Report attribute sector
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        validation_level (Any): Report attribute validation_level
        auth_tls_response (Any): Report attribute auth_tls_response
        auth_ssl_response (Any): Report attribute auth_ssl_response
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        jarm (Any): Report attribute jarm
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    response_size: Any
    configuration_naming_context: Any
    current_time: Any
    default_naming_context: Any
    dns_host_name: Any
    domain_controller_functionality: Any
    domain_functionality: Any
    ds_service_name: Any
    forest_functionality: Any
    highest_committed_usn: Any
    is_global_catalog_ready: Any
    is_synchronized: Any
    ldap_service_name: Any
    naming_contexts: Any
    root_domain_naming_context: Any
    schema_naming_context: Any
    server_name: Any
    subschema_subentry: Any
    supported_capabilities: Any
    supported_control: Any
    supported_ldap_policies: Any
    supported_ldap_version: Any
    supported_sasl_mechanisms: Any
    amplification: Any
    handshake: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sector: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    validation_level: Any
    auth_tls_response: Any
    auth_ssl_response: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    jarm: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any

class Scan6Mqtt:
    '''Representation of report IPv6-Open-MQTT with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        anonymous_access (Any): Report attribute anonymous_access
        raw_response (Any): Report attribute raw_response
        hex_code (Any): Report attribute hex_code
        code (Any): Report attribute code
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    anonymous_access: Any
    raw_response: Any
    hex_code: Any
    code: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sector: Any

class Scan6MqttAnon:
    '''Representation of report IPv6-Open-Anonymous-MQTT with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        raw_response (Any): Report attribute raw_response
        hex_code (Any): Report attribute hex_code
        code (Any): Report attribute code
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    raw_response: Any
    hex_code: Any
    code: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sector: Any

class Scan6Mysql:
    '''Representation of report IPv6-Accessible-MySQL with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        mysql_protocol_version (Any): Report attribute mysql_protocol_version
        server_version (Any): Report attribute server_version
        error_code (Any): Report attribute error_code
        error_id (Any): Report attribute error_id
        error_message (Any): Report attribute error_message
        client_can_handle_expired_passwords (Any): Report attribute client_can_handle_expired_passwords
        client_compress (Any): Report attribute client_compress
        client_connect_attrs (Any): Report attribute client_connect_attrs
        client_connect_with_db (Any): Report attribute client_connect_with_db
        client_deprecated_eof (Any): Report attribute client_deprecated_eof
        client_found_rows (Any): Report attribute client_found_rows
        client_ignore_sigpipe (Any): Report attribute client_ignore_sigpipe
        client_ignore_space (Any): Report attribute client_ignore_space
        client_interactive (Any): Report attribute client_interactive
        client_local_files (Any): Report attribute client_local_files
        client_long_flag (Any): Report attribute client_long_flag
        client_long_password (Any): Report attribute client_long_password
        client_multi_results (Any): Report attribute client_multi_results
        client_multi_statements (Any): Report attribute client_multi_statements
        client_no_schema (Any): Report attribute client_no_schema
        client_odbc (Any): Report attribute client_odbc
        client_plugin_auth (Any): Report attribute client_plugin_auth
        client_plugin_auth_len_enc_client_data (Any): Report attribute client_plugin_auth_len_enc_client_data
        client_protocol_41 (Any): Report attribute client_protocol_41
        client_ps_multi_results (Any): Report attribute client_ps_multi_results
        client_reserved (Any): Report attribute client_reserved
        client_secure_connection (Any): Report attribute client_secure_connection
        client_session_track (Any): Report attribute client_session_track
        client_ssl (Any): Report attribute client_ssl
        client_transactions (Any): Report attribute client_transactions
        handshake (Any): Report attribute handshake
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        validation_level (Any): Report attribute validation_level
        browser_trusted (Any): Report attribute browser_trusted
        browser_error (Any): Report attribute browser_error
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    mysql_protocol_version: Any
    server_version: Any
    error_code: Any
    error_id: Any
    error_message: Any
    client_can_handle_expired_passwords: Any
    client_compress: Any
    client_connect_attrs: Any
    client_connect_with_db: Any
    client_deprecated_eof: Any
    client_found_rows: Any
    client_ignore_sigpipe: Any
    client_ignore_space: Any
    client_interactive: Any
    client_local_files: Any
    client_long_flag: Any
    client_long_password: Any
    client_multi_results: Any
    client_multi_statements: Any
    client_no_schema: Any
    client_odbc: Any
    client_plugin_auth: Any
    client_plugin_auth_len_enc_client_data: Any
    client_protocol_41: Any
    client_ps_multi_results: Any
    client_reserved: Any
    client_secure_connection: Any
    client_session_track: Any
    client_ssl: Any
    client_transactions: Any
    handshake: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    validation_level: Any
    browser_trusted: Any
    browser_error: Any
    raw_cert: Any
    raw_cert_chain: Any

class Scan6Ntp:
    '''Representation of report IPv6-NTP-Version with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        version (Any): Report attribute version
        clk_wander (Any): Report attribute clk_wander
        clock (Any): Report attribute clock
        error (Any): Report attribute error
        frequency (Any): Report attribute frequency
        jitter (Any): Report attribute jitter
        leap (Any): Report attribute leap
        mintc (Any): Report attribute mintc
        noise (Any): Report attribute noise
        offset (Any): Report attribute offset
        peer (Any): Report attribute peer
        phase (Any): Report attribute phase
        poll (Any): Report attribute poll
        precision (Any): Report attribute precision
        processor (Any): Report attribute processor
        refid (Any): Report attribute refid
        reftime (Any): Report attribute reftime
        rootdelay (Any): Report attribute rootdelay
        rootdispersion (Any): Report attribute rootdispersion
        stability (Any): Report attribute stability
        state (Any): Report attribute state
        stratum (Any): Report attribute stratum
        system (Any): Report attribute system
        tai (Any): Report attribute tai
        tc (Any): Report attribute tc
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    version: Any
    clk_wander: Any
    clock: Any
    error: Any
    frequency: Any
    jitter: Any
    leap: Any
    mintc: Any
    noise: Any
    offset: Any
    peer: Any
    phase: Any
    poll: Any
    precision: Any
    processor: Any
    refid: Any
    reftime: Any
    rootdelay: Any
    rootdispersion: Any
    stability: Any
    state: Any
    stratum: Any
    system: Any
    tai: Any
    tc: Any
    naics: Any
    hostname_source: Any
    sector: Any
    response_size: Any
    amplification: Any

class Scan6Ntpmonitor:
    '''Representation of report IPv6-NTP-Monitor with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        packets (Any): Report attribute packets
        response_size (Any): Report attribute response_size
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    packets: Any
    response_size: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    amplification: Any

class Scan6Postgres:
    '''Representation of report IPv6-Accessible-PostgreSQL with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        supported_protocols (Any): Report attribute supported_protocols
        protocol_error_code (Any): Report attribute protocol_error_code
        protocol_error_file (Any): Report attribute protocol_error_file
        protocol_error_line (Any): Report attribute protocol_error_line
        protocol_error_message (Any): Report attribute protocol_error_message
        protocol_error_routine (Any): Report attribute protocol_error_routine
        protocol_error_severity (Any): Report attribute protocol_error_severity
        protocol_error_severity_v (Any): Report attribute protocol_error_severity_v
        startup_error_code (Any): Report attribute startup_error_code
        startup_error_file (Any): Report attribute startup_error_file
        startup_error_line (Any): Report attribute startup_error_line
        startup_error_message (Any): Report attribute startup_error_message
        startup_error_routine (Any): Report attribute startup_error_routine
        startup_error_severity (Any): Report attribute startup_error_severity
        startup_error_severity_v (Any): Report attribute startup_error_severity_v
        client_ssl (Any): Report attribute client_ssl
        handshake (Any): Report attribute handshake
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        validation_level (Any): Report attribute validation_level
        browser_trusted (Any): Report attribute browser_trusted
        browser_error (Any): Report attribute browser_error
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    supported_protocols: Any
    protocol_error_code: Any
    protocol_error_file: Any
    protocol_error_line: Any
    protocol_error_message: Any
    protocol_error_routine: Any
    protocol_error_severity: Any
    protocol_error_severity_v: Any
    startup_error_code: Any
    startup_error_file: Any
    startup_error_line: Any
    startup_error_message: Any
    startup_error_routine: Any
    startup_error_severity: Any
    startup_error_severity_v: Any
    client_ssl: Any
    handshake: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    validation_level: Any
    browser_trusted: Any
    browser_error: Any
    raw_cert: Any
    raw_cert_chain: Any

class Scan6Rdp:
    '''Representation of report IPv6-Accessible-RDP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        handshake (Any): Report attribute handshake
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        rdp_protocol (Any): Report attribute rdp_protocol
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        jarm (Any): Report attribute jarm
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    handshake: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    rdp_protocol: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    naics: Any
    hostname_source: Any
    sector: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    jarm: Any

class Scan6Slp:
    '''Representation of report IPv6-Accessible-SLP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        version (Any): Report attribute version
        function (Any): Report attribute function
        function_text (Any): Report attribute function_text
        flags (Any): Report attribute flags
        next_extension_offset (Any): Report attribute next_extension_offset
        xid (Any): Report attribute xid
        language_tag_length (Any): Report attribute language_tag_length
        language_tag (Any): Report attribute language_tag
        error_code (Any): Report attribute error_code
        error_code_text (Any): Report attribute error_code_text
        response_size (Any): Report attribute response_size
        raw_response (Any): Report attribute raw_response
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    version: Any
    function: Any
    function_text: Any
    flags: Any
    next_extension_offset: Any
    xid: Any
    language_tag_length: Any
    language_tag: Any
    error_code: Any
    error_code_text: Any
    response_size: Any
    raw_response: Any

class Scan6Smb:
    '''Representation of report IPv6-Accessible-SMB with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        arch (Any): Report attribute arch
        key (Any): Report attribute key
        smb_major_number (Any): Report attribute smb_major_number
        smb_minor_number (Any): Report attribute smb_minor_number
        smb_revision (Any): Report attribute smb_revision
        smb_version_string (Any): Report attribute smb_version_string
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    arch: Any
    key: Any
    smb_major_number: Any
    smb_minor_number: Any
    smb_revision: Any
    smb_version_string: Any
    sector: Any

class Scan6Smtp:
    '''Representation of report IPv6-Accessible-SMTP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        banner (Any): Report attribute banner
        sector (Any): Report attribute sector
        auth_ssl_response (Any): Report attribute auth_ssl_response
        auth_tls_response (Any): Report attribute auth_tls_response
        cert_expiration_date (Any): Report attribute cert_expiration_date
        cert_expired (Any): Report attribute cert_expired
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_length (Any): Report attribute cert_length
        cert_serial_number (Any): Report attribute cert_serial_number
        cert_valid (Any): Report attribute cert_valid
        cipher_suite (Any): Report attribute cipher_suite
        freak_cipher_suite (Any): Report attribute freak_cipher_suite
        freak_vulnerable (Any): Report attribute freak_vulnerable
        handshake (Any): Report attribute handshake
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_common_name (Any): Report attribute issuer_common_name
        issuer_country (Any): Report attribute issuer_country
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_serial_number (Any): Report attribute issuer_serial_number
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_surname (Any): Report attribute issuer_surname
        jarm (Any): Report attribute jarm
        key_algorithm (Any): Report attribute key_algorithm
        md5_fingerprint (Any): Report attribute md5_fingerprint
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
        self_signed (Any): Report attribute self_signed
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        signature_algorithm (Any): Report attribute signature_algorithm
        ssl_version (Any): Report attribute ssl_version
        sslv3_supported (Any): Report attribute sslv3_supported
        subject_business_category (Any): Report attribute subject_business_category
        subject_common_name (Any): Report attribute subject_common_name
        subject_country (Any): Report attribute subject_country
        subject_email_address (Any): Report attribute subject_email_address
        subject_given_name (Any): Report attribute subject_given_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_serial_number (Any): Report attribute subject_serial_number
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_surname (Any): Report attribute subject_surname
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        tlsv13_support (Any): Report attribute tlsv13_support
        validation_level (Any): Report attribute validation_level
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    banner: Any
    sector: Any
    auth_ssl_response: Any
    auth_tls_response: Any
    cert_expiration_date: Any
    cert_expired: Any
    cert_issue_date: Any
    cert_length: Any
    cert_serial_number: Any
    cert_valid: Any
    cipher_suite: Any
    freak_cipher_suite: Any
    freak_vulnerable: Any
    handshake: Any
    issuer_business_category: Any
    issuer_common_name: Any
    issuer_country: Any
    issuer_email_address: Any
    issuer_given_name: Any
    issuer_locality_name: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_postal_code: Any
    issuer_serial_number: Any
    issuer_state_or_province_name: Any
    issuer_street_address: Any
    issuer_surname: Any
    jarm: Any
    key_algorithm: Any
    md5_fingerprint: Any
    raw_cert: Any
    raw_cert_chain: Any
    self_signed: Any
    sha1_fingerprint: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    signature_algorithm: Any
    ssl_version: Any
    sslv3_supported: Any
    subject_business_category: Any
    subject_common_name: Any
    subject_country: Any
    subject_email_address: Any
    subject_given_name: Any
    subject_locality_name: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_postal_code: Any
    subject_serial_number: Any
    subject_state_or_province_name: Any
    subject_street_address: Any
    subject_surname: Any
    tlsv13_cipher: Any
    tlsv13_support: Any
    validation_level: Any

class Scan6SmtpVulnerable:
    '''Representation of report IPv6-Vulnerable-SMTP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        banner (Any): Report attribute banner
        sector (Any): Report attribute sector
        auth_ssl_response (Any): Report attribute auth_ssl_response
        auth_tls_response (Any): Report attribute auth_tls_response
        cert_expiration_date (Any): Report attribute cert_expiration_date
        cert_expired (Any): Report attribute cert_expired
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_length (Any): Report attribute cert_length
        cert_serial_number (Any): Report attribute cert_serial_number
        cert_valid (Any): Report attribute cert_valid
        cipher_suite (Any): Report attribute cipher_suite
        freak_cipher_suite (Any): Report attribute freak_cipher_suite
        freak_vulnerable (Any): Report attribute freak_vulnerable
        handshake (Any): Report attribute handshake
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_common_name (Any): Report attribute issuer_common_name
        issuer_country (Any): Report attribute issuer_country
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_serial_number (Any): Report attribute issuer_serial_number
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_surname (Any): Report attribute issuer_surname
        jarm (Any): Report attribute jarm
        key_algorithm (Any): Report attribute key_algorithm
        md5_fingerprint (Any): Report attribute md5_fingerprint
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
        self_signed (Any): Report attribute self_signed
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        signature_algorithm (Any): Report attribute signature_algorithm
        ssl_version (Any): Report attribute ssl_version
        sslv3_supported (Any): Report attribute sslv3_supported
        subject_business_category (Any): Report attribute subject_business_category
        subject_common_name (Any): Report attribute subject_common_name
        subject_country (Any): Report attribute subject_country
        subject_email_address (Any): Report attribute subject_email_address
        subject_given_name (Any): Report attribute subject_given_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_serial_number (Any): Report attribute subject_serial_number
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_surname (Any): Report attribute subject_surname
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        tlsv13_support (Any): Report attribute tlsv13_support
        validation_level (Any): Report attribute validation_level
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    banner: Any
    sector: Any
    auth_ssl_response: Any
    auth_tls_response: Any
    cert_expiration_date: Any
    cert_expired: Any
    cert_issue_date: Any
    cert_length: Any
    cert_serial_number: Any
    cert_valid: Any
    cipher_suite: Any
    freak_cipher_suite: Any
    freak_vulnerable: Any
    handshake: Any
    issuer_business_category: Any
    issuer_common_name: Any
    issuer_country: Any
    issuer_email_address: Any
    issuer_given_name: Any
    issuer_locality_name: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_postal_code: Any
    issuer_serial_number: Any
    issuer_state_or_province_name: Any
    issuer_street_address: Any
    issuer_surname: Any
    jarm: Any
    key_algorithm: Any
    md5_fingerprint: Any
    raw_cert: Any
    raw_cert_chain: Any
    self_signed: Any
    sha1_fingerprint: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    signature_algorithm: Any
    ssl_version: Any
    sslv3_supported: Any
    subject_business_category: Any
    subject_common_name: Any
    subject_country: Any
    subject_email_address: Any
    subject_given_name: Any
    subject_locality_name: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_postal_code: Any
    subject_serial_number: Any
    subject_state_or_province_name: Any
    subject_street_address: Any
    subject_surname: Any
    tlsv13_cipher: Any
    tlsv13_support: Any
    validation_level: Any

class Scan6Snmp:
    '''Representation of report IPv6-Open-SNMP with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        sysname (Any): Report attribute sysname
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        version (Any): Report attribute version
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
        sysdesc (Any): Report attribute sysdesc
        community (Any): Report attribute community
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
        uptime (Any): Report attribute uptime
        mac_address (Any): Report attribute mac_address
        vendor_id (Any): Report attribute vendor_id
        vendor (Any): Report attribute vendor
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    sysname: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    version: Any
    naics: Any
    hostname_source: Any
    sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any
    sysdesc: Any
    community: Any
    response_size: Any
    amplification: Any
    uptime: Any
    mac_address: Any
    vendor_id: Any
    vendor: Any

class Scan6Ssh:
    '''Representation of report IPv6-Accessible-SSH with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        serverid_raw (Any): Report attribute serverid_raw
        serverid_version (Any): Report attribute serverid_version
        serverid_software (Any): Report attribute serverid_software
        serverid_comment (Any): Report attribute serverid_comment
        server_cookie (Any): Report attribute server_cookie
        available_kex (Any): Report attribute available_kex
        available_ciphers (Any): Report attribute available_ciphers
        available_mac (Any): Report attribute available_mac
        available_compression (Any): Report attribute available_compression
        selected_kex (Any): Report attribute selected_kex
        algorithm (Any): Report attribute algorithm
        selected_cipher (Any): Report attribute selected_cipher
        selected_mac (Any): Report attribute selected_mac
        selected_compression (Any): Report attribute selected_compression
        server_signature_value (Any): Report attribute server_signature_value
        server_signature_raw (Any): Report attribute server_signature_raw
        server_host_key (Any): Report attribute server_host_key
        server_host_key_sha256 (Any): Report attribute server_host_key_sha256
        rsa_prime (Any): Report attribute rsa_prime
        rsa_prime_length (Any): Report attribute rsa_prime_length
        rsa_generator (Any): Report attribute rsa_generator
        rsa_generator_length (Any): Report attribute rsa_generator_length
        rsa_public_key (Any): Report attribute rsa_public_key
        rsa_public_key_length (Any): Report attribute rsa_public_key_length
        rsa_exponent (Any): Report attribute rsa_exponent
        rsa_modulus (Any): Report attribute rsa_modulus
        rsa_length (Any): Report attribute rsa_length
        dss_prime (Any): Report attribute dss_prime
        dss_prime_length (Any): Report attribute dss_prime_length
        dss_generator (Any): Report attribute dss_generator
        dss_generator_length (Any): Report attribute dss_generator_length
        dss_public_key (Any): Report attribute dss_public_key
        dss_public_key_length (Any): Report attribute dss_public_key_length
        dss_dsa_public_g (Any): Report attribute dss_dsa_public_g
        dss_dsa_public_p (Any): Report attribute dss_dsa_public_p
        dss_dsa_public_q (Any): Report attribute dss_dsa_public_q
        dss_dsa_public_y (Any): Report attribute dss_dsa_public_y
        ecdsa_curve25519 (Any): Report attribute ecdsa_curve25519
        ecdsa_curve (Any): Report attribute ecdsa_curve
        ecdsa_public_key_length (Any): Report attribute ecdsa_public_key_length
        ecdsa_public_key_b (Any): Report attribute ecdsa_public_key_b
        ecdsa_public_key_gx (Any): Report attribute ecdsa_public_key_gx
        ecdsa_public_key_gy (Any): Report attribute ecdsa_public_key_gy
        ecdsa_public_key_n (Any): Report attribute ecdsa_public_key_n
        ecdsa_public_key_p (Any): Report attribute ecdsa_public_key_p
        ecdsa_public_key_x (Any): Report attribute ecdsa_public_key_x
        ecdsa_public_key_y (Any): Report attribute ecdsa_public_key_y
        ed25519_curve25519 (Any): Report attribute ed25519_curve25519
        ed25519_cert_public_key_nonce (Any): Report attribute ed25519_cert_public_key_nonce
        ed25519_cert_public_key_bytes (Any): Report attribute ed25519_cert_public_key_bytes
        ed25519_cert_public_key_raw (Any): Report attribute ed25519_cert_public_key_raw
        ed25519_cert_public_key_sha256 (Any): Report attribute ed25519_cert_public_key_sha256
        ed25519_cert_public_key_serial (Any): Report attribute ed25519_cert_public_key_serial
        ed25519_cert_public_key_type_id (Any): Report attribute ed25519_cert_public_key_type_id
        ed25519_cert_public_key_type_name (Any): Report attribute ed25519_cert_public_key_type_name
        ed25519_cert_public_key_keyid (Any): Report attribute ed25519_cert_public_key_keyid
        ed25519_cert_public_key_principles (Any): Report attribute ed25519_cert_public_key_principles
        ed25519_cert_public_key_valid_after (Any): Report attribute ed25519_cert_public_key_valid_after
        ed25519_cert_public_key_valid_before (Any): Report attribute ed25519_cert_public_key_valid_before
        ed25519_cert_public_key_duration (Any): Report attribute ed25519_cert_public_key_duration
        ed25519_cert_public_key_sigkey_bytes (Any): Report attribute ed25519_cert_public_key_sigkey_bytes
        ed25519_cert_public_key_sigkey_raw (Any): Report attribute ed25519_cert_public_key_sigkey_raw
        ed25519_cert_public_key_sigkey_sha256 (Any): Report attribute ed25519_cert_public_key_sigkey_sha256
        ed25519_cert_public_key_sigkey_value (Any): Report attribute ed25519_cert_public_key_sigkey_value
        ed25519_cert_public_key_sig_raw (Any): Report attribute ed25519_cert_public_key_sig_raw
        banner (Any): Report attribute banner
        userauth_methods (Any): Report attribute userauth_methods
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    serverid_raw: Any
    serverid_version: Any
    serverid_software: Any
    serverid_comment: Any
    server_cookie: Any
    available_kex: Any
    available_ciphers: Any
    available_mac: Any
    available_compression: Any
    selected_kex: Any
    algorithm: Any
    selected_cipher: Any
    selected_mac: Any
    selected_compression: Any
    server_signature_value: Any
    server_signature_raw: Any
    server_host_key: Any
    server_host_key_sha256: Any
    rsa_prime: Any
    rsa_prime_length: Any
    rsa_generator: Any
    rsa_generator_length: Any
    rsa_public_key: Any
    rsa_public_key_length: Any
    rsa_exponent: Any
    rsa_modulus: Any
    rsa_length: Any
    dss_prime: Any
    dss_prime_length: Any
    dss_generator: Any
    dss_generator_length: Any
    dss_public_key: Any
    dss_public_key_length: Any
    dss_dsa_public_g: Any
    dss_dsa_public_p: Any
    dss_dsa_public_q: Any
    dss_dsa_public_y: Any
    ecdsa_curve25519: Any
    ecdsa_curve: Any
    ecdsa_public_key_length: Any
    ecdsa_public_key_b: Any
    ecdsa_public_key_gx: Any
    ecdsa_public_key_gy: Any
    ecdsa_public_key_n: Any
    ecdsa_public_key_p: Any
    ecdsa_public_key_x: Any
    ecdsa_public_key_y: Any
    ed25519_curve25519: Any
    ed25519_cert_public_key_nonce: Any
    ed25519_cert_public_key_bytes: Any
    ed25519_cert_public_key_raw: Any
    ed25519_cert_public_key_sha256: Any
    ed25519_cert_public_key_serial: Any
    ed25519_cert_public_key_type_id: Any
    ed25519_cert_public_key_type_name: Any
    ed25519_cert_public_key_keyid: Any
    ed25519_cert_public_key_principles: Any
    ed25519_cert_public_key_valid_after: Any
    ed25519_cert_public_key_valid_before: Any
    ed25519_cert_public_key_duration: Any
    ed25519_cert_public_key_sigkey_bytes: Any
    ed25519_cert_public_key_sigkey_raw: Any
    ed25519_cert_public_key_sigkey_sha256: Any
    ed25519_cert_public_key_sigkey_value: Any
    ed25519_cert_public_key_sig_raw: Any
    banner: Any
    userauth_methods: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any
    sector: Any

class Scan6Ssl:
    '''Representation of report IPv6-Accessible-SSL with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        handshake (Any): Report attribute handshake
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        cipher_suite (Any): Report attribute cipher_suite
        ssl_poodle (Any): Report attribute ssl_poodle
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        freak_vulnerable (Any): Report attribute freak_vulnerable
        freak_cipher_suite (Any): Report attribute freak_cipher_suite
        sector (Any): Report attribute sector
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        http_response_type (Any): Report attribute http_response_type
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        http_connection (Any): Report attribute http_connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server_type (Any): Report attribute server_type
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        browser_trusted (Any): Report attribute browser_trusted
        validation_level (Any): Report attribute validation_level
        browser_error (Any): Report attribute browser_error
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        jarm (Any): Report attribute jarm
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    handshake: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    cipher_suite: Any
    ssl_poodle: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    naics: Any
    hostname_source: Any
    freak_vulnerable: Any
    freak_cipher_suite: Any
    sector: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    http_response_type: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    http_connection: Any
    www_authenticate: Any
    set_cookie: Any
    server_type: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    browser_trusted: Any
    validation_level: Any
    browser_error: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    jarm: Any

class Scan6SslFreak:
    '''Representation of report SSL-FREAK-Vulnerable-Servers IPv6 with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        handshake (Any): Report attribute handshake
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        freak_vulnerable (Any): Report attribute freak_vulnerable
        freak_cipher_suite (Any): Report attribute freak_cipher_suite
        sector (Any): Report attribute sector
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        http_response_type (Any): Report attribute http_response_type
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        http_connection (Any): Report attribute http_connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server_type (Any): Report attribute server_type
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        browser_trusted (Any): Report attribute browser_trusted
        validation_level (Any): Report attribute validation_level
        browser_error (Any): Report attribute browser_error
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
        jarm (Any): Report attribute jarm
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
        page_sha256fp (Any): Report attribute page_sha256fp
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    handshake: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    naics: Any
    hostname_source: Any
    freak_vulnerable: Any
    freak_cipher_suite: Any
    sector: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    http_response_type: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    http_connection: Any
    www_authenticate: Any
    set_cookie: Any
    server_type: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    browser_trusted: Any
    validation_level: Any
    browser_error: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    raw_cert: Any
    raw_cert_chain: Any
    jarm: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any
    page_sha256fp: Any

class Scan6SslPoodle:
    '''Representation of report SSL-POODLE-Vulnerable-Servers IPv6 with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        handshake (Any): Report attribute handshake
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        cipher_suite (Any): Report attribute cipher_suite
        ssl_poodle (Any): Report attribute ssl_poodle
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        http_response_type (Any): Report attribute http_response_type
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        http_connection (Any): Report attribute http_connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server_type (Any): Report attribute server_type
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        browser_trusted (Any): Report attribute browser_trusted
        validation_level (Any): Report attribute validation_level
        browser_error (Any): Report attribute browser_error
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
        jarm (Any): Report attribute jarm
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
        page_sha256fp (Any): Report attribute page_sha256fp
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    handshake: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    cipher_suite: Any
    ssl_poodle: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    naics: Any
    hostname_source: Any
    sector: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    http_response_type: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    http_connection: Any
    www_authenticate: Any
    set_cookie: Any
    server_type: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    browser_trusted: Any
    validation_level: Any
    browser_error: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    raw_cert: Any
    raw_cert_chain: Any
    jarm: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any
    page_sha256fp: Any

class Scan6Stun:
    '''Representation of report IPv6-Accessible-Session-Traversal-Utilities-for-NAT with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        transaction_id (Any): Report attribute transaction_id
        magic_cookie (Any): Report attribute magic_cookie
        message_length (Any): Report attribute message_length
        message_type (Any): Report attribute message_type
        mapped_family (Any): Report attribute mapped_family
        mapped_address (Any): Report attribute mapped_address
        mapped_port (Any): Report attribute mapped_port
        xor_mapped_family (Any): Report attribute xor_mapped_family
        xor_mapped_address (Any): Report attribute xor_mapped_address
        xor_mapped_port (Any): Report attribute xor_mapped_port
        software (Any): Report attribute software
        fingerprint (Any): Report attribute fingerprint
        amplification (Any): Report attribute amplification
        response_size (Any): Report attribute response_size
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    transaction_id: Any
    magic_cookie: Any
    message_length: Any
    message_type: Any
    mapped_family: Any
    mapped_address: Any
    mapped_port: Any
    xor_mapped_family: Any
    xor_mapped_address: Any
    xor_mapped_port: Any
    software: Any
    fingerprint: Any
    amplification: Any
    response_size: Any

class Scan6Telnet:
    '''Representation of report IPv6-Accessible-Telnet with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        banner (Any): Report attribute banner
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    banner: Any
    sector: Any

class Scan6Vnc:
    '''Representation of report IPv6-Accessible-VNC with type undetermined and taxonomy other

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        product (Any): Report attribute product
        banner (Any): Report attribute banner
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    product: Any
    banner: Any
    sector: Any

class ScanActivemq:
    '''Representation of report Accessible-ActiveMQ with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-activemq-service-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        command (Any): Report attribute command
        vendor (Any): Report attribute vendor
        version (Any): Report attribute version
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    command: Any
    vendor: Any
    version: Any

class ScanAdb:
    '''Representation of report Accessible-ADB with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-adb-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        name (Any): Report attribute name
        model (Any): Report attribute model
        device (Any): Report attribute device
        features (Any): Report attribute features
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    name: Any
    model: Any
    device: Any
    features: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any
    sector: Any

class ScanAfp:
    '''Representation of report Accessible-AFP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-afp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        machine_type (Any): Report attribute machine_type
        afp_versions (Any): Report attribute afp_versions
        uams (Any): Report attribute uams
        flags (Any): Report attribute flags
        server_name (Any): Report attribute server_name
        signature (Any): Report attribute signature
        directory_service (Any): Report attribute directory_service
        utf8_servername (Any): Report attribute utf8_servername
        network_address (Any): Report attribute network_address
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    machine_type: Any
    afp_versions: Any
    uams: Any
    flags: Any
    server_name: Any
    signature: Any
    directory_service: Any
    utf8_servername: Any
    network_address: Any
    sector: Any

class ScanAmqp:
    '''Representation of report Accessible-AMQP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-amqp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        channel (Any): Report attribute channel
        message_length (Any): Report attribute message_length
        class (Any): Report attribute class
        method (Any): Report attribute method
        version_major (Any): Report attribute version_major
        version_minor (Any): Report attribute version_minor
        capabilities (Any): Report attribute capabilities
        cluster_name (Any): Report attribute cluster_name
        platform (Any): Report attribute platform
        product (Any): Report attribute product
        product_version (Any): Report attribute product_version
        mechanisms (Any): Report attribute mechanisms
        locales (Any): Report attribute locales
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    channel: Any
    message_length: Any
    method: Any
    version_major: Any
    version_minor: Any
    capabilities: Any
    cluster_name: Any
    platform: Any
    product: Any
    product_version: Any
    mechanisms: Any
    locales: Any
    sector: Any

class ScanArd:
    '''Representation of report Accessible-ARD with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-apple-remote-desktop-ard-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        machine_name (Any): Report attribute machine_name
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    machine_name: Any
    response_size: Any
    amplification: Any
    sector: Any

class ScanBgp:
    '''Representation of report Open-BGP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-bgp-service-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        message_length (Any): Report attribute message_length
        message_type (Any): Report attribute message_type
        message_type_int (Any): Report attribute message_type_int
        bgp_version (Any): Report attribute bgp_version
        sender_asn (Any): Report attribute sender_asn
        hold_time (Any): Report attribute hold_time
        bgp_identifier (Any): Report attribute bgp_identifier
        message2_type (Any): Report attribute message2_type
        message2_type_int (Any): Report attribute message2_type_int
        major_error_code (Any): Report attribute major_error_code
        major_error_code_int (Any): Report attribute major_error_code_int
        minor_error_code (Any): Report attribute minor_error_code
        minor_error_code_int (Any): Report attribute minor_error_code_int
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    message_length: Any
    message_type: Any
    message_type_int: Any
    bgp_version: Any
    sender_asn: Any
    hold_time: Any
    bgp_identifier: Any
    message2_type: Any
    message2_type_int: Any
    major_error_code: Any
    major_error_code_int: Any
    minor_error_code: Any
    minor_error_code_int: Any

class ScanChargen:
    '''Representation of report Open-Chargen with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-chargen-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    response_size: Any
    amplification: Any

class ScanCiscoSmartInstall:
    '''Representation of report Accessible-Cisco-Smart-Install with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-cisco-smart-install-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any

class ScanCoap:
    '''Representation of report Accessible-CoAP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-coap-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        response (Any): Report attribute response
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    response: Any
    response_size: Any
    amplification: Any
    sector: Any

class ScanCouchdb:
    '''Representation of report Accessible-CouchDB with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-couchdb-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        server_version (Any): Report attribute server_version
        couchdb_message (Any): Report attribute couchdb_message
        couchdb_version (Any): Report attribute couchdb_version
        git_sha (Any): Report attribute git_sha
        features (Any): Report attribute features
        vendor (Any): Report attribute vendor
        visible_databases (Any): Report attribute visible_databases
        error (Any): Report attribute error
        error_reason (Any): Report attribute error_reason
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    server_version: Any
    couchdb_message: Any
    couchdb_version: Any
    git_sha: Any
    features: Any
    vendor: Any
    visible_databases: Any
    error: Any
    error_reason: Any

class ScanCwmp:
    '''Representation of report Accessible-CWMP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-cwmp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        connection (Any): Report attribute connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server (Any): Report attribute server
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        date (Any): Report attribute date
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    connection: Any
    www_authenticate: Any
    set_cookie: Any
    server: Any
    content_length: Any
    transfer_encoding: Any
    date: Any
    sector: Any

class ScanDb2:
    '''Representation of report Open-DB2-Discovery-Service with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-db2-discovery-service-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        db2_hostname (Any): Report attribute db2_hostname
        servername (Any): Report attribute servername
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    db2_hostname: Any
    servername: Any
    response_size: Any
    amplification: Any
    sector: Any

class ScanDdosMiddlebox:
    '''Representation of report Vulnerable-DDoS-Middlebox with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/vulnerable-ddos-middlebox-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        source_port (Any): Report attribute source_port
        bytes (Any): Report attribute bytes
        amplification (Any): Report attribute amplification
        method (Any): Report attribute method
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    source_port: Any
    bytes: Any
    amplification: Any
    method: Any

class ScanDns:
    '''Representation of report DNS-Open-Resolvers with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/dns-open-resolvers-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        dns_version (Any): Report attribute dns_version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        min_amplification (Any): Report attribute min_amplification
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    dns_version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    min_amplification: Any
    naics: Any
    hostname_source: Any
    sector: Any

class ScanDocker:
    '''Representation of report Accessible-Docker with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-docker-service-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        server (Any): Report attribute server
        date (Any): Report attribute date
        experimental (Any): Report attribute experimental
        api_version (Any): Report attribute api_version
        arch (Any): Report attribute arch
        go_version (Any): Report attribute go_version
        os (Any): Report attribute os
        kernel_version (Any): Report attribute kernel_version
        git_commit (Any): Report attribute git_commit
        min_api_version (Any): Report attribute min_api_version
        build_time (Any): Report attribute build_time
        pkg_version (Any): Report attribute pkg_version
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    server: Any
    date: Any
    experimental: Any
    api_version: Any
    arch: Any
    go_version: Any
    os: Any
    kernel_version: Any
    git_commit: Any
    min_api_version: Any
    build_time: Any
    pkg_version: Any

class ScanDvrDhcpdiscover:
    '''Representation of report Accessible-DVR-DHCPDiscover with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-dvr-dhcpdiscover-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_id (Any): Report attribute device_id
        device_serial (Any): Report attribute device_serial
        machine_name (Any): Report attribute machine_name
        manufacturer (Any): Report attribute manufacturer
        method (Any): Report attribute method
        http_port (Any): Report attribute http_port
        internal_port (Any): Report attribute internal_port
        video_input_channels (Any): Report attribute video_input_channels
        alarm_input_channels (Any): Report attribute alarm_input_channels
        video_output_channels (Any): Report attribute video_output_channels
        alarm_output_channels (Any): Report attribute alarm_output_channels
        remote_video_input_channels (Any): Report attribute remote_video_input_channels
        mac_address (Any): Report attribute mac_address
        ipv4_address (Any): Report attribute ipv4_address
        ipv4_gateway (Any): Report attribute ipv4_gateway
        ipv4_subnet_mask (Any): Report attribute ipv4_subnet_mask
        ipv4_dhcp_enable (Any): Report attribute ipv4_dhcp_enable
        ipv6_address (Any): Report attribute ipv6_address
        ipv6_link_local (Any): Report attribute ipv6_link_local
        ipv6_gateway (Any): Report attribute ipv6_gateway
        ipv6_dhcp_enable (Any): Report attribute ipv6_dhcp_enable
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_id: Any
    device_serial: Any
    machine_name: Any
    manufacturer: Any
    method: Any
    http_port: Any
    internal_port: Any
    video_input_channels: Any
    alarm_input_channels: Any
    video_output_channels: Any
    alarm_output_channels: Any
    remote_video_input_channels: Any
    mac_address: Any
    ipv4_address: Any
    ipv4_gateway: Any
    ipv4_subnet_mask: Any
    ipv4_dhcp_enable: Any
    ipv6_address: Any
    ipv6_link_local: Any
    ipv6_gateway: Any
    ipv6_dhcp_enable: Any
    response_size: Any
    amplification: Any

class ScanElasticsearch:
    '''Representation of report Open-Elasticsearch with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-elasticsearch-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        ok (Any): Report attribute ok
        name (Any): Report attribute name
        cluster_name (Any): Report attribute cluster_name
        http_code (Any): Report attribute http_code
        build_hash (Any): Report attribute build_hash
        build_timestamp (Any): Report attribute build_timestamp
        build_snapshot (Any): Report attribute build_snapshot
        lucene_version (Any): Report attribute lucene_version
        tagline (Any): Report attribute tagline
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    ok: Any
    name: Any
    cluster_name: Any
    http_code: Any
    build_hash: Any
    build_timestamp: Any
    build_snapshot: Any
    lucene_version: Any
    tagline: Any
    sector: Any

class ScanEpmd:
    '''Representation of report Accessible-Erlang-Port-Mapper-Daemon with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-erlang-port-mapper-report-daemon/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        nodes (Any): Report attribute nodes
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    nodes: Any

class ScanExchange:
    '''Representation of report Vulnerable-Exchange-Server with type undetermined and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/vulnerable-exchange-server-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        version (Any): Report attribute version
        servername (Any): Report attribute servername
        url (Any): Report attribute url
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    version: Any
    servername: Any
    url: Any

class ScanFtp:
    '''Representation of report Accessible-FTP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-ftp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        banner (Any): Report attribute banner
        handshake (Any): Report attribute handshake
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        validation_level (Any): Report attribute validation_level
        auth_tls_response (Any): Report attribute auth_tls_response
        auth_ssl_response (Any): Report attribute auth_ssl_response
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        jarm (Any): Report attribute jarm
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    banner: Any
    handshake: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    validation_level: Any
    auth_tls_response: Any
    auth_ssl_response: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    jarm: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any

class ScanHadoop:
    '''Representation of report Accessible-Hadoop with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-hadoop-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        server_type (Any): Report attribute server_type
        clusterid (Any): Report attribute clusterid
        total_disk (Any): Report attribute total_disk
        used_disk (Any): Report attribute used_disk
        free_disk (Any): Report attribute free_disk
        livenodes (Any): Report attribute livenodes
        namenodeaddress (Any): Report attribute namenodeaddress
        volumeinfo (Any): Report attribute volumeinfo
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    server_type: Any
    clusterid: Any
    total_disk: Any
    used_disk: Any
    free_disk: Any
    livenodes: Any
    namenodeaddress: Any
    volumeinfo: Any
    sector: Any

class ScanHttp:
    '''Representation of report Accessible-HTTP with type other and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-http-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        sector (Any): Report attribute sector
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        connection (Any): Report attribute connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server (Any): Report attribute server
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    sector: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    connection: Any
    www_authenticate: Any
    set_cookie: Any
    server: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any

class ScanHttpProxy:
    '''Representation of report Open-HTTP-Proxy with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-http-proxy-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        sector (Any): Report attribute sector
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        connection (Any): Report attribute connection
        proxy_authenticate (Any): Report attribute proxy_authenticate
        via (Any): Report attribute via
        server (Any): Report attribute server
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    sector: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    connection: Any
    proxy_authenticate: Any
    via: Any
    server: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any

class ScanHttpVulnerable:
    '''Representation of report Vulnerable-HTTP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/vulnerable-http-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        sector (Any): Report attribute sector
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        connection (Any): Report attribute connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server (Any): Report attribute server
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
        version (Any): Report attribute version
        build_date (Any): Report attribute build_date
        detail (Any): Report attribute detail
        build_branch (Any): Report attribute build_branch
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    sector: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    connection: Any
    www_authenticate: Any
    set_cookie: Any
    server: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any
    version: Any
    build_date: Any
    detail: Any
    build_branch: Any

class ScanIcs:
    '''Representation of report Accessible-ICS with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-ics-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_id (Any): Report attribute device_id
        response_size (Any): Report attribute response_size
        raw_response (Any): Report attribute raw_response
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_id: Any
    response_size: Any
    raw_response: Any

class ScanIpmi:
    '''Representation of report Open-IPMI with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-ipmi-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        ipmi_version (Any): Report attribute ipmi_version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        none_auth (Any): Report attribute none_auth
        md2_auth (Any): Report attribute md2_auth
        md5_auth (Any): Report attribute md5_auth
        passkey_auth (Any): Report attribute passkey_auth
        oem_auth (Any): Report attribute oem_auth
        defaultkg (Any): Report attribute defaultkg
        permessage_auth (Any): Report attribute permessage_auth
        userlevel_auth (Any): Report attribute userlevel_auth
        usernames (Any): Report attribute usernames
        nulluser (Any): Report attribute nulluser
        anon_login (Any): Report attribute anon_login
        error (Any): Report attribute error
        deviceid (Any): Report attribute deviceid
        devicerev (Any): Report attribute devicerev
        firmwarerev (Any): Report attribute firmwarerev
        version (Any): Report attribute version
        manufacturerid (Any): Report attribute manufacturerid
        manufacturername (Any): Report attribute manufacturername
        productid (Any): Report attribute productid
        productname (Any): Report attribute productname
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    ipmi_version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    none_auth: Any
    md2_auth: Any
    md5_auth: Any
    passkey_auth: Any
    oem_auth: Any
    defaultkg: Any
    permessage_auth: Any
    userlevel_auth: Any
    usernames: Any
    nulluser: Any
    anon_login: Any
    error: Any
    deviceid: Any
    devicerev: Any
    firmwarerev: Any
    version: Any
    manufacturerid: Any
    manufacturername: Any
    productid: Any
    productname: Any
    naics: Any
    hostname_source: Any
    sector: Any

class ScanIpp:
    '''Representation of report Open-IPP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-ipp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        ipp_version (Any): Report attribute ipp_version
        cups_version (Any): Report attribute cups_version
        printer_uris (Any): Report attribute printer_uris
        printer_name (Any): Report attribute printer_name
        printer_info (Any): Report attribute printer_info
        printer_more_info (Any): Report attribute printer_more_info
        printer_make_and_model (Any): Report attribute printer_make_and_model
        printer_firmware_name (Any): Report attribute printer_firmware_name
        printer_firmware_string_version (Any): Report attribute printer_firmware_string_version
        printer_firmware_version (Any): Report attribute printer_firmware_version
        printer_organization (Any): Report attribute printer_organization
        printer_organization_unit (Any): Report attribute printer_organization_unit
        printer_uuid (Any): Report attribute printer_uuid
        printer_wifi_ssid (Any): Report attribute printer_wifi_ssid
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    ipp_version: Any
    cups_version: Any
    printer_uris: Any
    printer_name: Any
    printer_info: Any
    printer_more_info: Any
    printer_make_and_model: Any
    printer_firmware_name: Any
    printer_firmware_string_version: Any
    printer_firmware_version: Any
    printer_organization: Any
    printer_organization_unit: Any
    printer_uuid: Any
    printer_wifi_ssid: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any
    sector: Any

class ScanIsakmp:
    '''Representation of report Vulnerable-ISAKMP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/vulnerable-isakmp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        initiator_spi (Any): Report attribute initiator_spi
        responder_spi (Any): Report attribute responder_spi
        next_payload (Any): Report attribute next_payload
        exchange_type (Any): Report attribute exchange_type
        flags (Any): Report attribute flags
        message_id (Any): Report attribute message_id
        next_payload2 (Any): Report attribute next_payload2
        domain_of_interpretation (Any): Report attribute domain_of_interpretation
        protocol_id (Any): Report attribute protocol_id
        spi_size (Any): Report attribute spi_size
        notify_message_type (Any): Report attribute notify_message_type
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    initiator_spi: Any
    responder_spi: Any
    next_payload: Any
    exchange_type: Any
    flags: Any
    message_id: Any
    next_payload2: Any
    domain_of_interpretation: Any
    protocol_id: Any
    spi_size: Any
    notify_message_type: Any
    sector: Any

class ScanKubernetes:
    '''Representation of report Accessible-Kubernetes-API with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-kubernetes-api-server-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        http (Any): Report attribute http
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        server (Any): Report attribute server
        date (Any): Report attribute date
        major (Any): Report attribute major
        minor (Any): Report attribute minor
        git_version (Any): Report attribute git_version
        git_commit (Any): Report attribute git_commit
        git_tree_state (Any): Report attribute git_tree_state
        build_date (Any): Report attribute build_date
        go_version (Any): Report attribute go_version
        compiler (Any): Report attribute compiler
        platform (Any): Report attribute platform
        handshake (Any): Report attribute handshake
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        validation_level (Any): Report attribute validation_level
        browser_trusted (Any): Report attribute browser_trusted
        browser_error (Any): Report attribute browser_error
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    http: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    server: Any
    date: Any
    major: Any
    minor: Any
    git_version: Any
    git_commit: Any
    git_tree_state: Any
    build_date: Any
    go_version: Any
    compiler: Any
    platform: Any
    handshake: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    validation_level: Any
    browser_trusted: Any
    browser_error: Any
    raw_cert: Any
    raw_cert_chain: Any

class ScanLdapTcp:
    '''Representation of report Open-LDAP-TCP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-ldap-tcp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        response_size (Any): Report attribute response_size
        configuration_naming_context (Any): Report attribute configuration_naming_context
        current_time (Any): Report attribute current_time
        default_naming_context (Any): Report attribute default_naming_context
        dns_host_name (Any): Report attribute dns_host_name
        domain_controller_functionality (Any): Report attribute domain_controller_functionality
        domain_functionality (Any): Report attribute domain_functionality
        ds_service_name (Any): Report attribute ds_service_name
        forest_functionality (Any): Report attribute forest_functionality
        highest_committed_usn (Any): Report attribute highest_committed_usn
        is_global_catalog_ready (Any): Report attribute is_global_catalog_ready
        is_synchronized (Any): Report attribute is_synchronized
        ldap_service_name (Any): Report attribute ldap_service_name
        naming_contexts (Any): Report attribute naming_contexts
        root_domain_naming_context (Any): Report attribute root_domain_naming_context
        schema_naming_context (Any): Report attribute schema_naming_context
        server_name (Any): Report attribute server_name
        subschema_subentry (Any): Report attribute subschema_subentry
        supported_capabilities (Any): Report attribute supported_capabilities
        supported_control (Any): Report attribute supported_control
        supported_ldap_policies (Any): Report attribute supported_ldap_policies
        supported_ldap_version (Any): Report attribute supported_ldap_version
        supported_sasl_mechanisms (Any): Report attribute supported_sasl_mechanisms
        amplification (Any): Report attribute amplification
        handshake (Any): Report attribute handshake
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sector (Any): Report attribute sector
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        validation_level (Any): Report attribute validation_level
        auth_tls_response (Any): Report attribute auth_tls_response
        auth_ssl_response (Any): Report attribute auth_ssl_response
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        jarm (Any): Report attribute jarm
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    response_size: Any
    configuration_naming_context: Any
    current_time: Any
    default_naming_context: Any
    dns_host_name: Any
    domain_controller_functionality: Any
    domain_functionality: Any
    ds_service_name: Any
    forest_functionality: Any
    highest_committed_usn: Any
    is_global_catalog_ready: Any
    is_synchronized: Any
    ldap_service_name: Any
    naming_contexts: Any
    root_domain_naming_context: Any
    schema_naming_context: Any
    server_name: Any
    subschema_subentry: Any
    supported_capabilities: Any
    supported_control: Any
    supported_ldap_policies: Any
    supported_ldap_version: Any
    supported_sasl_mechanisms: Any
    amplification: Any
    handshake: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sector: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    validation_level: Any
    auth_tls_response: Any
    auth_ssl_response: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    jarm: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any

class ScanLdapUdp:
    '''Representation of report Open-LDAP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-ldap-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        response_size (Any): Report attribute response_size
        configuration_naming_context (Any): Report attribute configuration_naming_context
        current_time (Any): Report attribute current_time
        default_naming_context (Any): Report attribute default_naming_context
        dns_host_name (Any): Report attribute dns_host_name
        domain_controller_functionality (Any): Report attribute domain_controller_functionality
        domain_functionality (Any): Report attribute domain_functionality
        ds_service_name (Any): Report attribute ds_service_name
        forest_functionality (Any): Report attribute forest_functionality
        highest_committed_usn (Any): Report attribute highest_committed_usn
        is_global_catalog_ready (Any): Report attribute is_global_catalog_ready
        is_synchronized (Any): Report attribute is_synchronized
        ldap_service_name (Any): Report attribute ldap_service_name
        naming_contexts (Any): Report attribute naming_contexts
        root_domain_naming_context (Any): Report attribute root_domain_naming_context
        schema_naming_context (Any): Report attribute schema_naming_context
        server_name (Any): Report attribute server_name
        subschema_subentry (Any): Report attribute subschema_subentry
        supported_capabilities (Any): Report attribute supported_capabilities
        supported_control (Any): Report attribute supported_control
        supported_ldap_policies (Any): Report attribute supported_ldap_policies
        supported_ldap_version (Any): Report attribute supported_ldap_version
        supported_sasl_mechanisms (Any): Report attribute supported_sasl_mechanisms
        amplification (Any): Report attribute amplification
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    response_size: Any
    configuration_naming_context: Any
    current_time: Any
    default_naming_context: Any
    dns_host_name: Any
    domain_controller_functionality: Any
    domain_functionality: Any
    ds_service_name: Any
    forest_functionality: Any
    highest_committed_usn: Any
    is_global_catalog_ready: Any
    is_synchronized: Any
    ldap_service_name: Any
    naming_contexts: Any
    root_domain_naming_context: Any
    schema_naming_context: Any
    server_name: Any
    subschema_subentry: Any
    supported_capabilities: Any
    supported_control: Any
    supported_ldap_policies: Any
    supported_ldap_version: Any
    supported_sasl_mechanisms: Any
    amplification: Any
    sector: Any

class ScanMdns:
    '''Representation of report Open-mDNS with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-mdns-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        mdns_name (Any): Report attribute mdns_name
        mdns_ipv4 (Any): Report attribute mdns_ipv4
        mdns_ipv6 (Any): Report attribute mdns_ipv6
        services (Any): Report attribute services
        workstation_name (Any): Report attribute workstation_name
        workstation_ipv4 (Any): Report attribute workstation_ipv4
        workstation_ipv6 (Any): Report attribute workstation_ipv6
        workstation_info (Any): Report attribute workstation_info
        http_name (Any): Report attribute http_name
        http_ipv4 (Any): Report attribute http_ipv4
        http_ipv6 (Any): Report attribute http_ipv6
        http_ptr (Any): Report attribute http_ptr
        http_info (Any): Report attribute http_info
        http_target (Any): Report attribute http_target
        http_port (Any): Report attribute http_port
        spotify_name (Any): Report attribute spotify_name
        spotify_ipv4 (Any): Report attribute spotify_ipv4
        spotify_ipv6 (Any): Report attribute spotify_ipv6
        opc_ua_discovery (Any): Report attribute opc_ua_discovery
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    mdns_name: Any
    mdns_ipv4: Any
    mdns_ipv6: Any
    services: Any
    workstation_name: Any
    workstation_ipv4: Any
    workstation_ipv6: Any
    workstation_info: Any
    http_name: Any
    http_ipv4: Any
    http_ipv6: Any
    http_ptr: Any
    http_info: Any
    http_target: Any
    http_port: Any
    spotify_name: Any
    spotify_ipv4: Any
    spotify_ipv6: Any
    opc_ua_discovery: Any
    sector: Any

class ScanMemcached:
    '''Representation of report Open-Memcached with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-memcached-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        pid (Any): Report attribute pid
        pointer_size (Any): Report attribute pointer_size
        uptime (Any): Report attribute uptime
        time (Any): Report attribute time
        curr_connections (Any): Report attribute curr_connections
        total_connections (Any): Report attribute total_connections
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    pid: Any
    pointer_size: Any
    uptime: Any
    time: Any
    curr_connections: Any
    total_connections: Any
    sector: Any
    response_size: Any
    amplification: Any

class ScanMongodb:
    '''Representation of report Open-MongoDB with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-mongodb-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        gitversion (Any): Report attribute gitversion
        sysinfo (Any): Report attribute sysinfo
        opensslversion (Any): Report attribute opensslversion
        allocator (Any): Report attribute allocator
        javascriptengine (Any): Report attribute javascriptengine
        bits (Any): Report attribute bits
        maxbsonobjectsize (Any): Report attribute maxbsonobjectsize
        ok (Any): Report attribute ok
        visible_databases (Any): Report attribute visible_databases
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    gitversion: Any
    sysinfo: Any
    opensslversion: Any
    allocator: Any
    javascriptengine: Any
    bits: Any
    maxbsonobjectsize: Any
    ok: Any
    visible_databases: Any
    sector: Any

class ScanMqtt:
    '''Representation of report Open-MQTT with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-mqtt-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        anonymous_access (Any): Report attribute anonymous_access
        raw_response (Any): Report attribute raw_response
        hex_code (Any): Report attribute hex_code
        code (Any): Report attribute code
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    anonymous_access: Any
    raw_response: Any
    hex_code: Any
    code: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sector: Any

class ScanMqttAnon:
    '''Representation of report Open-Anonymous-MQTT with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-mqtt-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        raw_response (Any): Report attribute raw_response
        hex_code (Any): Report attribute hex_code
        code (Any): Report attribute code
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    raw_response: Any
    hex_code: Any
    code: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sector: Any

class ScanMssql:
    '''Representation of report Open-MSSQL with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-ms-sql-server-resolution-service-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        server_name (Any): Report attribute server_name
        instance_name (Any): Report attribute instance_name
        tcp_port (Any): Report attribute tcp_port
        named_pipe (Any): Report attribute named_pipe
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    server_name: Any
    instance_name: Any
    tcp_port: Any
    named_pipe: Any
    response_size: Any
    amplification: Any
    sector: Any

class ScanMysql:
    '''Representation of report Accessible-MySQL with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-mysql-server-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        mysql_protocol_version (Any): Report attribute mysql_protocol_version
        server_version (Any): Report attribute server_version
        error_code (Any): Report attribute error_code
        error_id (Any): Report attribute error_id
        error_message (Any): Report attribute error_message
        client_can_handle_expired_passwords (Any): Report attribute client_can_handle_expired_passwords
        client_compress (Any): Report attribute client_compress
        client_connect_attrs (Any): Report attribute client_connect_attrs
        client_connect_with_db (Any): Report attribute client_connect_with_db
        client_deprecated_eof (Any): Report attribute client_deprecated_eof
        client_found_rows (Any): Report attribute client_found_rows
        client_ignore_sigpipe (Any): Report attribute client_ignore_sigpipe
        client_ignore_space (Any): Report attribute client_ignore_space
        client_interactive (Any): Report attribute client_interactive
        client_local_files (Any): Report attribute client_local_files
        client_long_flag (Any): Report attribute client_long_flag
        client_long_password (Any): Report attribute client_long_password
        client_multi_results (Any): Report attribute client_multi_results
        client_multi_statements (Any): Report attribute client_multi_statements
        client_no_schema (Any): Report attribute client_no_schema
        client_odbc (Any): Report attribute client_odbc
        client_plugin_auth (Any): Report attribute client_plugin_auth
        client_plugin_auth_len_enc_client_data (Any): Report attribute client_plugin_auth_len_enc_client_data
        client_protocol_41 (Any): Report attribute client_protocol_41
        client_ps_multi_results (Any): Report attribute client_ps_multi_results
        client_reserved (Any): Report attribute client_reserved
        client_secure_connection (Any): Report attribute client_secure_connection
        client_session_track (Any): Report attribute client_session_track
        client_ssl (Any): Report attribute client_ssl
        client_transactions (Any): Report attribute client_transactions
        handshake (Any): Report attribute handshake
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        validation_level (Any): Report attribute validation_level
        browser_trusted (Any): Report attribute browser_trusted
        browser_error (Any): Report attribute browser_error
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    mysql_protocol_version: Any
    server_version: Any
    error_code: Any
    error_id: Any
    error_message: Any
    client_can_handle_expired_passwords: Any
    client_compress: Any
    client_connect_attrs: Any
    client_connect_with_db: Any
    client_deprecated_eof: Any
    client_found_rows: Any
    client_ignore_sigpipe: Any
    client_ignore_space: Any
    client_interactive: Any
    client_local_files: Any
    client_long_flag: Any
    client_long_password: Any
    client_multi_results: Any
    client_multi_statements: Any
    client_no_schema: Any
    client_odbc: Any
    client_plugin_auth: Any
    client_plugin_auth_len_enc_client_data: Any
    client_protocol_41: Any
    client_ps_multi_results: Any
    client_reserved: Any
    client_secure_connection: Any
    client_session_track: Any
    client_ssl: Any
    client_transactions: Any
    handshake: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    validation_level: Any
    browser_trusted: Any
    browser_error: Any
    raw_cert: Any
    raw_cert_chain: Any

class ScanNatPmp:
    '''Representation of report Open-NATPMP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-nat-pmp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        opcode (Any): Report attribute opcode
        uptime (Any): Report attribute uptime
        external_ip (Any): Report attribute external_ip
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    opcode: Any
    uptime: Any
    external_ip: Any
    sector: Any
    response_size: Any
    amplification: Any

class ScanNetbios:
    '''Representation of report Open-NetBIOS-Nameservice with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-netbios-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        mac_address (Any): Report attribute mac_address
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        workgroup (Any): Report attribute workgroup
        machine_name (Any): Report attribute machine_name
        username (Any): Report attribute username
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    mac_address: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    workgroup: Any
    machine_name: Any
    username: Any
    naics: Any
    hostname_source: Any
    sector: Any
    response_size: Any
    amplification: Any

class ScanNetisRouter:
    '''Representation of report Open-Netis with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/netcore-netis-router-vulnerability-scan-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        response (Any): Report attribute response
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    response: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    response_size: Any
    amplification: Any

class ScanNtp:
    '''Representation of report NTP-Version with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/ntp-version-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        version (Any): Report attribute version
        clk_wander (Any): Report attribute clk_wander
        clock (Any): Report attribute clock
        error (Any): Report attribute error
        frequency (Any): Report attribute frequency
        jitter (Any): Report attribute jitter
        leap (Any): Report attribute leap
        mintc (Any): Report attribute mintc
        noise (Any): Report attribute noise
        offset (Any): Report attribute offset
        peer (Any): Report attribute peer
        phase (Any): Report attribute phase
        poll (Any): Report attribute poll
        precision (Any): Report attribute precision
        processor (Any): Report attribute processor
        refid (Any): Report attribute refid
        reftime (Any): Report attribute reftime
        rootdelay (Any): Report attribute rootdelay
        rootdispersion (Any): Report attribute rootdispersion
        stability (Any): Report attribute stability
        state (Any): Report attribute state
        stratum (Any): Report attribute stratum
        system (Any): Report attribute system
        tai (Any): Report attribute tai
        tc (Any): Report attribute tc
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    version: Any
    clk_wander: Any
    clock: Any
    error: Any
    frequency: Any
    jitter: Any
    leap: Any
    mintc: Any
    noise: Any
    offset: Any
    peer: Any
    phase: Any
    poll: Any
    precision: Any
    processor: Any
    refid: Any
    reftime: Any
    rootdelay: Any
    rootdispersion: Any
    stability: Any
    state: Any
    stratum: Any
    system: Any
    tai: Any
    tc: Any
    naics: Any
    hostname_source: Any
    sector: Any
    response_size: Any
    amplification: Any

class ScanNtpmonitor:
    '''Representation of report NTP-Monitor with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/ntp-monitor-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        packets (Any): Report attribute packets
        response_size (Any): Report attribute response_size
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    packets: Any
    response_size: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    amplification: Any

class ScanPortmapper:
    '''Representation of report Open-Portmapper with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-portmapper-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        programs (Any): Report attribute programs
        mountd_port (Any): Report attribute mountd_port
        exports (Any): Report attribute exports
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    programs: Any
    mountd_port: Any
    exports: Any
    sector: Any
    response_size: Any
    amplification: Any

class ScanPostExploitationFramework:
    '''Representation of report Post-Exploitation-Framework with type infected-system and taxonomy malicious-code

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/post-exploitation-framework/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        http (Any): Report attribute http
        http_url (Any): Report attribute http_url
        http_code (Any): Report attribute http_code
        content_type (Any): Report attribute content_type
        content_length (Any): Report attribute content_length
        architecture (Any): Report attribute architecture
        beacon_type (Any): Report attribute beacon_type
        beacon_host (Any): Report attribute beacon_host
        beacon_port (Any): Report attribute beacon_port
        beacon_http_get (Any): Report attribute beacon_http_get
        beacon_http_post (Any): Report attribute beacon_http_post
        license_id (Any): Report attribute license_id
        config_md5 (Any): Report attribute config_md5
        config_sha1 (Any): Report attribute config_sha1
        config_sha256 (Any): Report attribute config_sha256
        config_sha512 (Any): Report attribute config_sha512
        binary_md5 (Any): Report attribute binary_md5
        binary_sha1 (Any): Report attribute binary_sha1
        binary_sha256 (Any): Report attribute binary_sha256
        binary_sha512 (Any): Report attribute binary_sha512
        encoded_length (Any): Report attribute encoded_length
        encoded_data (Any): Report attribute encoded_data
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    http: Any
    http_url: Any
    http_code: Any
    content_type: Any
    content_length: Any
    architecture: Any
    beacon_type: Any
    beacon_host: Any
    beacon_port: Any
    beacon_http_get: Any
    beacon_http_post: Any
    license_id: Any
    config_md5: Any
    config_sha1: Any
    config_sha256: Any
    config_sha512: Any
    binary_md5: Any
    binary_sha1: Any
    binary_sha256: Any
    binary_sha512: Any
    encoded_length: Any
    encoded_data: Any

class ScanPostgres:
    '''Representation of report Accessible-PostgreSQL with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-postgresql-server-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        supported_protocols (Any): Report attribute supported_protocols
        protocol_error_code (Any): Report attribute protocol_error_code
        protocol_error_file (Any): Report attribute protocol_error_file
        protocol_error_line (Any): Report attribute protocol_error_line
        protocol_error_message (Any): Report attribute protocol_error_message
        protocol_error_routine (Any): Report attribute protocol_error_routine
        protocol_error_severity (Any): Report attribute protocol_error_severity
        protocol_error_severity_v (Any): Report attribute protocol_error_severity_v
        startup_error_code (Any): Report attribute startup_error_code
        startup_error_file (Any): Report attribute startup_error_file
        startup_error_line (Any): Report attribute startup_error_line
        startup_error_message (Any): Report attribute startup_error_message
        startup_error_routine (Any): Report attribute startup_error_routine
        startup_error_severity (Any): Report attribute startup_error_severity
        startup_error_severity_v (Any): Report attribute startup_error_severity_v
        client_ssl (Any): Report attribute client_ssl
        handshake (Any): Report attribute handshake
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        validation_level (Any): Report attribute validation_level
        browser_trusted (Any): Report attribute browser_trusted
        browser_error (Any): Report attribute browser_error
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    supported_protocols: Any
    protocol_error_code: Any
    protocol_error_file: Any
    protocol_error_line: Any
    protocol_error_message: Any
    protocol_error_routine: Any
    protocol_error_severity: Any
    protocol_error_severity_v: Any
    startup_error_code: Any
    startup_error_file: Any
    startup_error_line: Any
    startup_error_message: Any
    startup_error_routine: Any
    startup_error_severity: Any
    startup_error_severity_v: Any
    client_ssl: Any
    handshake: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    validation_level: Any
    browser_trusted: Any
    browser_error: Any
    raw_cert: Any
    raw_cert_chain: Any

class ScanQotd:
    '''Representation of report Open-QOTD with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-qotd-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        quote (Any): Report attribute quote
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    quote: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    response_size: Any
    amplification: Any

class ScanQuic:
    '''Representation of report Accessible-QUIC with type other and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-quic-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        version_field_1 (Any): Report attribute version_field_1
        version_field_2 (Any): Report attribute version_field_2
        version_field_3 (Any): Report attribute version_field_3
        version_field_4 (Any): Report attribute version_field_4
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    version_field_1: Any
    version_field_2: Any
    version_field_3: Any
    version_field_4: Any
    sector: Any

class ScanRadmin:
    '''Representation of report Accessible-Radmin with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-radmin-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any

class ScanRdp:
    '''Representation of report Accessible-RDP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-rdp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        handshake (Any): Report attribute handshake
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        rdp_protocol (Any): Report attribute rdp_protocol
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        jarm (Any): Report attribute jarm
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    handshake: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    rdp_protocol: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    naics: Any
    hostname_source: Any
    sector: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    jarm: Any

class ScanRdpeudp:
    '''Representation of report Accessible-MS-RDPEUDP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-ms-rdpeudp/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sessionid (Any): Report attribute sessionid
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sessionid: Any
    response_size: Any
    amplification: Any
    sector: Any

class ScanRedis:
    '''Representation of report Open-Redis with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-redis-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        version (Any): Report attribute version
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        git_sha1 (Any): Report attribute git_sha1
        git_dirty_flag (Any): Report attribute git_dirty_flag
        build_id (Any): Report attribute build_id
        mode (Any): Report attribute mode
        os (Any): Report attribute os
        architecture (Any): Report attribute architecture
        multiplexing_api (Any): Report attribute multiplexing_api
        gcc_version (Any): Report attribute gcc_version
        process_id (Any): Report attribute process_id
        run_id (Any): Report attribute run_id
        uptime (Any): Report attribute uptime
        connected_clients (Any): Report attribute connected_clients
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    version: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    git_sha1: Any
    git_dirty_flag: Any
    build_id: Any
    mode: Any
    os: Any
    architecture: Any
    multiplexing_api: Any
    gcc_version: Any
    process_id: Any
    run_id: Any
    uptime: Any
    connected_clients: Any
    sector: Any

class ScanRsync:
    '''Representation of report Accessible-Rsync with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-rsync-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        module (Any): Report attribute module
        motd (Any): Report attribute motd
        has_password (Any): Report attribute has_password
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    module: Any
    motd: Any
    has_password: Any
    sector: Any

class ScanSip:
    '''Representation of report Accessible-SIP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-sip-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        sip (Any): Report attribute sip
        sip_code (Any): Report attribute sip_code
        sip_reason (Any): Report attribute sip_reason
        user_agent (Any): Report attribute user_agent
        sip_via (Any): Report attribute sip_via
        sip_to (Any): Report attribute sip_to
        sip_from (Any): Report attribute sip_from
        content_length (Any): Report attribute content_length
        content_type (Any): Report attribute content_type
        server (Any): Report attribute server
        contact (Any): Report attribute contact
        cseq (Any): Report attribute cseq
        call_id (Any): Report attribute call_id
        allow (Any): Report attribute allow
        amplification (Any): Report attribute amplification
        response_size (Any): Report attribute response_size
        hostname_source (Any): Report attribute hostname_source
        naics (Any): Report attribute naics
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    sip: Any
    sip_code: Any
    sip_reason: Any
    user_agent: Any
    sip_via: Any
    sip_to: Any
    sip_from: Any
    content_length: Any
    content_type: Any
    server: Any
    contact: Any
    cseq: Any
    call_id: Any
    allow: Any
    amplification: Any
    response_size: Any
    hostname_source: Any
    naics: Any
    sector: Any

class ScanSlp:
    '''Representation of report Accessible-SLP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-slp-service-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        version (Any): Report attribute version
        function (Any): Report attribute function
        function_text (Any): Report attribute function_text
        flags (Any): Report attribute flags
        next_extension_offset (Any): Report attribute next_extension_offset
        xid (Any): Report attribute xid
        language_tag_length (Any): Report attribute language_tag_length
        language_tag (Any): Report attribute language_tag
        error_code (Any): Report attribute error_code
        error_code_text (Any): Report attribute error_code_text
        response_size (Any): Report attribute response_size
        raw_response (Any): Report attribute raw_response
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    version: Any
    function: Any
    function_text: Any
    flags: Any
    next_extension_offset: Any
    xid: Any
    language_tag_length: Any
    language_tag: Any
    error_code: Any
    error_code_text: Any
    response_size: Any
    raw_response: Any

class ScanSmb:
    '''Representation of report Accessible-SMB with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-smb-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        arch (Any): Report attribute arch
        key (Any): Report attribute key
        smb_major_number (Any): Report attribute smb_major_number
        smb_minor_number (Any): Report attribute smb_minor_number
        smb_revision (Any): Report attribute smb_revision
        smb_version_string (Any): Report attribute smb_version_string
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    arch: Any
    key: Any
    smb_major_number: Any
    smb_minor_number: Any
    smb_revision: Any
    smb_version_string: Any
    sector: Any

class ScanSmtp:
    '''Representation of report Accessible-SMTP with type other and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-smtp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        banner (Any): Report attribute banner
        sector (Any): Report attribute sector
        auth_ssl_response (Any): Report attribute auth_ssl_response
        auth_tls_response (Any): Report attribute auth_tls_response
        cert_expiration_date (Any): Report attribute cert_expiration_date
        cert_expired (Any): Report attribute cert_expired
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_length (Any): Report attribute cert_length
        cert_serial_number (Any): Report attribute cert_serial_number
        cert_valid (Any): Report attribute cert_valid
        cipher_suite (Any): Report attribute cipher_suite
        freak_cipher_suite (Any): Report attribute freak_cipher_suite
        freak_vulnerable (Any): Report attribute freak_vulnerable
        handshake (Any): Report attribute handshake
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_common_name (Any): Report attribute issuer_common_name
        issuer_country (Any): Report attribute issuer_country
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_serial_number (Any): Report attribute issuer_serial_number
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_surname (Any): Report attribute issuer_surname
        jarm (Any): Report attribute jarm
        key_algorithm (Any): Report attribute key_algorithm
        md5_fingerprint (Any): Report attribute md5_fingerprint
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
        self_signed (Any): Report attribute self_signed
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        signature_algorithm (Any): Report attribute signature_algorithm
        ssl_version (Any): Report attribute ssl_version
        sslv3_supported (Any): Report attribute sslv3_supported
        subject_business_category (Any): Report attribute subject_business_category
        subject_common_name (Any): Report attribute subject_common_name
        subject_country (Any): Report attribute subject_country
        subject_email_address (Any): Report attribute subject_email_address
        subject_given_name (Any): Report attribute subject_given_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_serial_number (Any): Report attribute subject_serial_number
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_surname (Any): Report attribute subject_surname
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        tlsv13_support (Any): Report attribute tlsv13_support
        validation_level (Any): Report attribute validation_level
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    banner: Any
    sector: Any
    auth_ssl_response: Any
    auth_tls_response: Any
    cert_expiration_date: Any
    cert_expired: Any
    cert_issue_date: Any
    cert_length: Any
    cert_serial_number: Any
    cert_valid: Any
    cipher_suite: Any
    freak_cipher_suite: Any
    freak_vulnerable: Any
    handshake: Any
    issuer_business_category: Any
    issuer_common_name: Any
    issuer_country: Any
    issuer_email_address: Any
    issuer_given_name: Any
    issuer_locality_name: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_postal_code: Any
    issuer_serial_number: Any
    issuer_state_or_province_name: Any
    issuer_street_address: Any
    issuer_surname: Any
    jarm: Any
    key_algorithm: Any
    md5_fingerprint: Any
    raw_cert: Any
    raw_cert_chain: Any
    self_signed: Any
    sha1_fingerprint: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    signature_algorithm: Any
    ssl_version: Any
    sslv3_supported: Any
    subject_business_category: Any
    subject_common_name: Any
    subject_country: Any
    subject_email_address: Any
    subject_given_name: Any
    subject_locality_name: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_postal_code: Any
    subject_serial_number: Any
    subject_state_or_province_name: Any
    subject_street_address: Any
    subject_surname: Any
    tlsv13_cipher: Any
    tlsv13_support: Any
    validation_level: Any

class ScanSmtpVulnerable:
    '''Representation of report Vulnerable-SMTP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/vulnerable-smtp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        banner (Any): Report attribute banner
        sector (Any): Report attribute sector
        auth_ssl_response (Any): Report attribute auth_ssl_response
        auth_tls_response (Any): Report attribute auth_tls_response
        cert_expiration_date (Any): Report attribute cert_expiration_date
        cert_expired (Any): Report attribute cert_expired
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_length (Any): Report attribute cert_length
        cert_serial_number (Any): Report attribute cert_serial_number
        cert_valid (Any): Report attribute cert_valid
        cipher_suite (Any): Report attribute cipher_suite
        freak_cipher_suite (Any): Report attribute freak_cipher_suite
        freak_vulnerable (Any): Report attribute freak_vulnerable
        handshake (Any): Report attribute handshake
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_common_name (Any): Report attribute issuer_common_name
        issuer_country (Any): Report attribute issuer_country
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_serial_number (Any): Report attribute issuer_serial_number
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_surname (Any): Report attribute issuer_surname
        jarm (Any): Report attribute jarm
        key_algorithm (Any): Report attribute key_algorithm
        md5_fingerprint (Any): Report attribute md5_fingerprint
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
        self_signed (Any): Report attribute self_signed
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        signature_algorithm (Any): Report attribute signature_algorithm
        ssl_version (Any): Report attribute ssl_version
        sslv3_supported (Any): Report attribute sslv3_supported
        subject_business_category (Any): Report attribute subject_business_category
        subject_common_name (Any): Report attribute subject_common_name
        subject_country (Any): Report attribute subject_country
        subject_email_address (Any): Report attribute subject_email_address
        subject_given_name (Any): Report attribute subject_given_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_serial_number (Any): Report attribute subject_serial_number
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_surname (Any): Report attribute subject_surname
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        tlsv13_support (Any): Report attribute tlsv13_support
        validation_level (Any): Report attribute validation_level
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    banner: Any
    sector: Any
    auth_ssl_response: Any
    auth_tls_response: Any
    cert_expiration_date: Any
    cert_expired: Any
    cert_issue_date: Any
    cert_length: Any
    cert_serial_number: Any
    cert_valid: Any
    cipher_suite: Any
    freak_cipher_suite: Any
    freak_vulnerable: Any
    handshake: Any
    issuer_business_category: Any
    issuer_common_name: Any
    issuer_country: Any
    issuer_email_address: Any
    issuer_given_name: Any
    issuer_locality_name: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_postal_code: Any
    issuer_serial_number: Any
    issuer_state_or_province_name: Any
    issuer_street_address: Any
    issuer_surname: Any
    jarm: Any
    key_algorithm: Any
    md5_fingerprint: Any
    raw_cert: Any
    raw_cert_chain: Any
    self_signed: Any
    sha1_fingerprint: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    signature_algorithm: Any
    ssl_version: Any
    sslv3_supported: Any
    subject_business_category: Any
    subject_common_name: Any
    subject_country: Any
    subject_email_address: Any
    subject_given_name: Any
    subject_locality_name: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_postal_code: Any
    subject_serial_number: Any
    subject_state_or_province_name: Any
    subject_street_address: Any
    subject_surname: Any
    tlsv13_cipher: Any
    tlsv13_support: Any
    validation_level: Any

class ScanSnmp:
    '''Representation of report Open-SNMP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-snmp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        sysname (Any): Report attribute sysname
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        version (Any): Report attribute version
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
        sysdesc (Any): Report attribute sysdesc
        community (Any): Report attribute community
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
        uptime (Any): Report attribute uptime
        mac_address (Any): Report attribute mac_address
        vendor_id (Any): Report attribute vendor_id
        vendor (Any): Report attribute vendor
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    sysname: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    version: Any
    naics: Any
    hostname_source: Any
    sector: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any
    sysdesc: Any
    community: Any
    response_size: Any
    amplification: Any
    uptime: Any
    mac_address: Any
    vendor_id: Any
    vendor: Any

class ScanSocks:
    '''Representation of report Accessible-SOCKS4/5-Proxy with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-socks4-5-proxy-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any

class ScanSsdp:
    '''Representation of report Open-SSDP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-ssdp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        header (Any): Report attribute header
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        systime (Any): Report attribute systime
        cache_control (Any): Report attribute cache_control
        location (Any): Report attribute location
        server (Any): Report attribute server
        search_target (Any): Report attribute search_target
        unique_service_name (Any): Report attribute unique_service_name
        host (Any): Report attribute host
        nts (Any): Report attribute nts
        nt (Any): Report attribute nt
        content_type (Any): Report attribute content_type
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        server_port (Any): Report attribute server_port
        instance (Any): Report attribute instance
        version (Any): Report attribute version
        updated_at (Any): Report attribute updated_at
        resource_identifier (Any): Report attribute resource_identifier
        amplification (Any): Report attribute amplification
        response_size (Any): Report attribute response_size
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    header: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    systime: Any
    cache_control: Any
    location: Any
    server: Any
    search_target: Any
    unique_service_name: Any
    host: Any
    nts: Any
    nt: Any
    content_type: Any
    naics: Any
    hostname_source: Any
    sector: Any
    server_port: Any
    instance: Any
    version: Any
    updated_at: Any
    resource_identifier: Any
    amplification: Any
    response_size: Any

class ScanSsh:
    '''Representation of report Accessible-SSH with type other and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-ssh-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        serverid_raw (Any): Report attribute serverid_raw
        serverid_version (Any): Report attribute serverid_version
        serverid_software (Any): Report attribute serverid_software
        serverid_comment (Any): Report attribute serverid_comment
        server_cookie (Any): Report attribute server_cookie
        available_kex (Any): Report attribute available_kex
        available_ciphers (Any): Report attribute available_ciphers
        available_mac (Any): Report attribute available_mac
        available_compression (Any): Report attribute available_compression
        selected_kex (Any): Report attribute selected_kex
        algorithm (Any): Report attribute algorithm
        selected_cipher (Any): Report attribute selected_cipher
        selected_mac (Any): Report attribute selected_mac
        selected_compression (Any): Report attribute selected_compression
        server_signature_value (Any): Report attribute server_signature_value
        server_signature_raw (Any): Report attribute server_signature_raw
        server_host_key (Any): Report attribute server_host_key
        server_host_key_sha256 (Any): Report attribute server_host_key_sha256
        rsa_prime (Any): Report attribute rsa_prime
        rsa_prime_length (Any): Report attribute rsa_prime_length
        rsa_generator (Any): Report attribute rsa_generator
        rsa_generator_length (Any): Report attribute rsa_generator_length
        rsa_public_key (Any): Report attribute rsa_public_key
        rsa_public_key_length (Any): Report attribute rsa_public_key_length
        rsa_exponent (Any): Report attribute rsa_exponent
        rsa_modulus (Any): Report attribute rsa_modulus
        rsa_length (Any): Report attribute rsa_length
        dss_prime (Any): Report attribute dss_prime
        dss_prime_length (Any): Report attribute dss_prime_length
        dss_generator (Any): Report attribute dss_generator
        dss_generator_length (Any): Report attribute dss_generator_length
        dss_public_key (Any): Report attribute dss_public_key
        dss_public_key_length (Any): Report attribute dss_public_key_length
        dss_dsa_public_g (Any): Report attribute dss_dsa_public_g
        dss_dsa_public_p (Any): Report attribute dss_dsa_public_p
        dss_dsa_public_q (Any): Report attribute dss_dsa_public_q
        dss_dsa_public_y (Any): Report attribute dss_dsa_public_y
        ecdsa_curve25519 (Any): Report attribute ecdsa_curve25519
        ecdsa_curve (Any): Report attribute ecdsa_curve
        ecdsa_public_key_length (Any): Report attribute ecdsa_public_key_length
        ecdsa_public_key_b (Any): Report attribute ecdsa_public_key_b
        ecdsa_public_key_gx (Any): Report attribute ecdsa_public_key_gx
        ecdsa_public_key_gy (Any): Report attribute ecdsa_public_key_gy
        ecdsa_public_key_n (Any): Report attribute ecdsa_public_key_n
        ecdsa_public_key_p (Any): Report attribute ecdsa_public_key_p
        ecdsa_public_key_x (Any): Report attribute ecdsa_public_key_x
        ecdsa_public_key_y (Any): Report attribute ecdsa_public_key_y
        ed25519_curve25519 (Any): Report attribute ed25519_curve25519
        ed25519_cert_public_key_nonce (Any): Report attribute ed25519_cert_public_key_nonce
        ed25519_cert_public_key_bytes (Any): Report attribute ed25519_cert_public_key_bytes
        ed25519_cert_public_key_raw (Any): Report attribute ed25519_cert_public_key_raw
        ed25519_cert_public_key_sha256 (Any): Report attribute ed25519_cert_public_key_sha256
        ed25519_cert_public_key_serial (Any): Report attribute ed25519_cert_public_key_serial
        ed25519_cert_public_key_type_id (Any): Report attribute ed25519_cert_public_key_type_id
        ed25519_cert_public_key_type_name (Any): Report attribute ed25519_cert_public_key_type_name
        ed25519_cert_public_key_keyid (Any): Report attribute ed25519_cert_public_key_keyid
        ed25519_cert_public_key_principles (Any): Report attribute ed25519_cert_public_key_principles
        ed25519_cert_public_key_valid_after (Any): Report attribute ed25519_cert_public_key_valid_after
        ed25519_cert_public_key_valid_before (Any): Report attribute ed25519_cert_public_key_valid_before
        ed25519_cert_public_key_duration (Any): Report attribute ed25519_cert_public_key_duration
        ed25519_cert_public_key_sigkey_bytes (Any): Report attribute ed25519_cert_public_key_sigkey_bytes
        ed25519_cert_public_key_sigkey_raw (Any): Report attribute ed25519_cert_public_key_sigkey_raw
        ed25519_cert_public_key_sigkey_sha256 (Any): Report attribute ed25519_cert_public_key_sigkey_sha256
        ed25519_cert_public_key_sigkey_value (Any): Report attribute ed25519_cert_public_key_sigkey_value
        ed25519_cert_public_key_sig_raw (Any): Report attribute ed25519_cert_public_key_sig_raw
        banner (Any): Report attribute banner
        userauth_methods (Any): Report attribute userauth_methods
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    serverid_raw: Any
    serverid_version: Any
    serverid_software: Any
    serverid_comment: Any
    server_cookie: Any
    available_kex: Any
    available_ciphers: Any
    available_mac: Any
    available_compression: Any
    selected_kex: Any
    algorithm: Any
    selected_cipher: Any
    selected_mac: Any
    selected_compression: Any
    server_signature_value: Any
    server_signature_raw: Any
    server_host_key: Any
    server_host_key_sha256: Any
    rsa_prime: Any
    rsa_prime_length: Any
    rsa_generator: Any
    rsa_generator_length: Any
    rsa_public_key: Any
    rsa_public_key_length: Any
    rsa_exponent: Any
    rsa_modulus: Any
    rsa_length: Any
    dss_prime: Any
    dss_prime_length: Any
    dss_generator: Any
    dss_generator_length: Any
    dss_public_key: Any
    dss_public_key_length: Any
    dss_dsa_public_g: Any
    dss_dsa_public_p: Any
    dss_dsa_public_q: Any
    dss_dsa_public_y: Any
    ecdsa_curve25519: Any
    ecdsa_curve: Any
    ecdsa_public_key_length: Any
    ecdsa_public_key_b: Any
    ecdsa_public_key_gx: Any
    ecdsa_public_key_gy: Any
    ecdsa_public_key_n: Any
    ecdsa_public_key_p: Any
    ecdsa_public_key_x: Any
    ecdsa_public_key_y: Any
    ed25519_curve25519: Any
    ed25519_cert_public_key_nonce: Any
    ed25519_cert_public_key_bytes: Any
    ed25519_cert_public_key_raw: Any
    ed25519_cert_public_key_sha256: Any
    ed25519_cert_public_key_serial: Any
    ed25519_cert_public_key_type_id: Any
    ed25519_cert_public_key_type_name: Any
    ed25519_cert_public_key_keyid: Any
    ed25519_cert_public_key_principles: Any
    ed25519_cert_public_key_valid_after: Any
    ed25519_cert_public_key_valid_before: Any
    ed25519_cert_public_key_duration: Any
    ed25519_cert_public_key_sigkey_bytes: Any
    ed25519_cert_public_key_sigkey_raw: Any
    ed25519_cert_public_key_sigkey_sha256: Any
    ed25519_cert_public_key_sigkey_value: Any
    ed25519_cert_public_key_sig_raw: Any
    banner: Any
    userauth_methods: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any
    sector: Any

class ScanSsl:
    '''Representation of report Accessible-SSL with type other and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-ssl-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        handshake (Any): Report attribute handshake
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        cipher_suite (Any): Report attribute cipher_suite
        ssl_poodle (Any): Report attribute ssl_poodle
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        freak_vulnerable (Any): Report attribute freak_vulnerable
        freak_cipher_suite (Any): Report attribute freak_cipher_suite
        sector (Any): Report attribute sector
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        http_response_type (Any): Report attribute http_response_type
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        http_connection (Any): Report attribute http_connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server_type (Any): Report attribute server_type
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        browser_trusted (Any): Report attribute browser_trusted
        validation_level (Any): Report attribute validation_level
        browser_error (Any): Report attribute browser_error
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        jarm (Any): Report attribute jarm
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    handshake: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    cipher_suite: Any
    ssl_poodle: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    naics: Any
    hostname_source: Any
    freak_vulnerable: Any
    freak_cipher_suite: Any
    sector: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    http_response_type: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    http_connection: Any
    www_authenticate: Any
    set_cookie: Any
    server_type: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    browser_trusted: Any
    validation_level: Any
    browser_error: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    jarm: Any

class ScanSslFreak:
    '''Representation of report SSL-FREAK-Vulnerable-Servers with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/ssl-freak-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        handshake (Any): Report attribute handshake
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        cipher_suite (Any): Report attribute cipher_suite
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        freak_vulnerable (Any): Report attribute freak_vulnerable
        freak_cipher_suite (Any): Report attribute freak_cipher_suite
        sector (Any): Report attribute sector
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        http_response_type (Any): Report attribute http_response_type
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        http_connection (Any): Report attribute http_connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server_type (Any): Report attribute server_type
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        browser_trusted (Any): Report attribute browser_trusted
        validation_level (Any): Report attribute validation_level
        browser_error (Any): Report attribute browser_error
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
        jarm (Any): Report attribute jarm
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
        page_sha256fp (Any): Report attribute page_sha256fp
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    handshake: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    cipher_suite: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    naics: Any
    hostname_source: Any
    freak_vulnerable: Any
    freak_cipher_suite: Any
    sector: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    http_response_type: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    http_connection: Any
    www_authenticate: Any
    set_cookie: Any
    server_type: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    browser_trusted: Any
    validation_level: Any
    browser_error: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    raw_cert: Any
    raw_cert_chain: Any
    jarm: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any
    page_sha256fp: Any

class ScanSslPoodle:
    '''Representation of report SSL-POODLE-Vulnerable-Servers IPv4 with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/ssl-poodle-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        handshake (Any): Report attribute handshake
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        cipher_suite (Any): Report attribute cipher_suite
        ssl_poodle (Any): Report attribute ssl_poodle
        cert_length (Any): Report attribute cert_length
        subject_common_name (Any): Report attribute subject_common_name
        issuer_common_name (Any): Report attribute issuer_common_name
        cert_issue_date (Any): Report attribute cert_issue_date
        cert_expiration_date (Any): Report attribute cert_expiration_date
        sha1_fingerprint (Any): Report attribute sha1_fingerprint
        cert_serial_number (Any): Report attribute cert_serial_number
        ssl_version (Any): Report attribute ssl_version
        signature_algorithm (Any): Report attribute signature_algorithm
        key_algorithm (Any): Report attribute key_algorithm
        subject_organization_name (Any): Report attribute subject_organization_name
        subject_organization_unit_name (Any): Report attribute subject_organization_unit_name
        subject_country (Any): Report attribute subject_country
        subject_state_or_province_name (Any): Report attribute subject_state_or_province_name
        subject_locality_name (Any): Report attribute subject_locality_name
        subject_street_address (Any): Report attribute subject_street_address
        subject_postal_code (Any): Report attribute subject_postal_code
        subject_surname (Any): Report attribute subject_surname
        subject_given_name (Any): Report attribute subject_given_name
        subject_email_address (Any): Report attribute subject_email_address
        subject_business_category (Any): Report attribute subject_business_category
        subject_serial_number (Any): Report attribute subject_serial_number
        issuer_organization_name (Any): Report attribute issuer_organization_name
        issuer_organization_unit_name (Any): Report attribute issuer_organization_unit_name
        issuer_country (Any): Report attribute issuer_country
        issuer_state_or_province_name (Any): Report attribute issuer_state_or_province_name
        issuer_locality_name (Any): Report attribute issuer_locality_name
        issuer_street_address (Any): Report attribute issuer_street_address
        issuer_postal_code (Any): Report attribute issuer_postal_code
        issuer_surname (Any): Report attribute issuer_surname
        issuer_given_name (Any): Report attribute issuer_given_name
        issuer_email_address (Any): Report attribute issuer_email_address
        issuer_business_category (Any): Report attribute issuer_business_category
        issuer_serial_number (Any): Report attribute issuer_serial_number
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        sha256_fingerprint (Any): Report attribute sha256_fingerprint
        sha512_fingerprint (Any): Report attribute sha512_fingerprint
        md5_fingerprint (Any): Report attribute md5_fingerprint
        http_response_type (Any): Report attribute http_response_type
        http_code (Any): Report attribute http_code
        http_reason (Any): Report attribute http_reason
        content_type (Any): Report attribute content_type
        http_connection (Any): Report attribute http_connection
        www_authenticate (Any): Report attribute www_authenticate
        set_cookie (Any): Report attribute set_cookie
        server_type (Any): Report attribute server_type
        content_length (Any): Report attribute content_length
        transfer_encoding (Any): Report attribute transfer_encoding
        http_date (Any): Report attribute http_date
        cert_valid (Any): Report attribute cert_valid
        self_signed (Any): Report attribute self_signed
        cert_expired (Any): Report attribute cert_expired
        browser_trusted (Any): Report attribute browser_trusted
        validation_level (Any): Report attribute validation_level
        browser_error (Any): Report attribute browser_error
        tlsv13_support (Any): Report attribute tlsv13_support
        tlsv13_cipher (Any): Report attribute tlsv13_cipher
        raw_cert (Any): Report attribute raw_cert
        raw_cert_chain (Any): Report attribute raw_cert_chain
        jarm (Any): Report attribute jarm
        device_vendor (Any): Report attribute device_vendor
        device_type (Any): Report attribute device_type
        device_model (Any): Report attribute device_model
        device_version (Any): Report attribute device_version
        device_sector (Any): Report attribute device_sector
        page_sha256fp (Any): Report attribute page_sha256fp
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    handshake: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    cipher_suite: Any
    ssl_poodle: Any
    cert_length: Any
    subject_common_name: Any
    issuer_common_name: Any
    cert_issue_date: Any
    cert_expiration_date: Any
    sha1_fingerprint: Any
    cert_serial_number: Any
    ssl_version: Any
    signature_algorithm: Any
    key_algorithm: Any
    subject_organization_name: Any
    subject_organization_unit_name: Any
    subject_country: Any
    subject_state_or_province_name: Any
    subject_locality_name: Any
    subject_street_address: Any
    subject_postal_code: Any
    subject_surname: Any
    subject_given_name: Any
    subject_email_address: Any
    subject_business_category: Any
    subject_serial_number: Any
    issuer_organization_name: Any
    issuer_organization_unit_name: Any
    issuer_country: Any
    issuer_state_or_province_name: Any
    issuer_locality_name: Any
    issuer_street_address: Any
    issuer_postal_code: Any
    issuer_surname: Any
    issuer_given_name: Any
    issuer_email_address: Any
    issuer_business_category: Any
    issuer_serial_number: Any
    naics: Any
    hostname_source: Any
    sector: Any
    sha256_fingerprint: Any
    sha512_fingerprint: Any
    md5_fingerprint: Any
    http_response_type: Any
    http_code: Any
    http_reason: Any
    content_type: Any
    http_connection: Any
    www_authenticate: Any
    set_cookie: Any
    server_type: Any
    content_length: Any
    transfer_encoding: Any
    http_date: Any
    cert_valid: Any
    self_signed: Any
    cert_expired: Any
    browser_trusted: Any
    validation_level: Any
    browser_error: Any
    tlsv13_support: Any
    tlsv13_cipher: Any
    raw_cert: Any
    raw_cert_chain: Any
    jarm: Any
    device_vendor: Any
    device_type: Any
    device_model: Any
    device_version: Any
    device_sector: Any
    page_sha256fp: Any

class ScanStun:
    '''Representation of report Accessible-Session-Traversal-Utilities-for-NAT with type other and taxonomy other

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-stun-service-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        transaction_id (Any): Report attribute transaction_id
        magic_cookie (Any): Report attribute magic_cookie
        message_length (Any): Report attribute message_length
        message_type (Any): Report attribute message_type
        mapped_family (Any): Report attribute mapped_family
        mapped_address (Any): Report attribute mapped_address
        mapped_port (Any): Report attribute mapped_port
        xor_mapped_family (Any): Report attribute xor_mapped_family
        xor_mapped_address (Any): Report attribute xor_mapped_address
        xor_mapped_port (Any): Report attribute xor_mapped_port
        software (Any): Report attribute software
        fingerprint (Any): Report attribute fingerprint
        amplification (Any): Report attribute amplification
        response_size (Any): Report attribute response_size
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    transaction_id: Any
    magic_cookie: Any
    message_length: Any
    message_type: Any
    mapped_family: Any
    mapped_address: Any
    mapped_port: Any
    xor_mapped_family: Any
    xor_mapped_address: Any
    xor_mapped_port: Any
    software: Any
    fingerprint: Any
    amplification: Any
    response_size: Any

class ScanSynfulknock:
    '''Representation of report SYNful-Knock with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/synful-scan-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sequence_number (Any): Report attribute sequence_number
        ack_number (Any): Report attribute ack_number
        window_size (Any): Report attribute window_size
        urgent_pointer (Any): Report attribute urgent_pointer
        tcp_flags (Any): Report attribute tcp_flags
        raw_packet (Any): Report attribute raw_packet
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sequence_number: Any
    ack_number: Any
    window_size: Any
    urgent_pointer: Any
    tcp_flags: Any
    raw_packet: Any
    sector: Any

class ScanTelnet:
    '''Representation of report Accessible-Telnet with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-telnet-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        banner (Any): Report attribute banner
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    banner: Any
    sector: Any

class ScanTftp:
    '''Representation of report Open-TFTP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-accessible-tftp-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        opcode (Any): Report attribute opcode
        errorcode (Any): Report attribute errorcode
        error (Any): Report attribute error
        errormessage (Any): Report attribute errormessage
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    opcode: Any
    errorcode: Any
    error: Any
    errormessage: Any
    response_size: Any
    amplification: Any
    sector: Any

class ScanUbiquiti:
    '''Representation of report Accessible-Ubiquiti-Discovery-Service with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/open-ubiquiti-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        mac (Any): Report attribute mac
        radioname (Any): Report attribute radioname
        essid (Any): Report attribute essid
        modelshort (Any): Report attribute modelshort
        modelfull (Any): Report attribute modelfull
        firmware (Any): Report attribute firmware
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    mac: Any
    radioname: Any
    essid: Any
    modelshort: Any
    modelfull: Any
    firmware: Any
    response_size: Any
    amplification: Any
    sector: Any

class ScanVnc:
    '''Representation of report Accessible-VNC with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-vnc-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        product (Any): Report attribute product
        banner (Any): Report attribute banner
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    product: Any
    banner: Any
    sector: Any

class ScanWsDiscovery:
    '''Representation of report Accessible-WS-Discovery-Service with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-ws-discovery-service-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        sector (Any): Report attribute sector
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
        error (Any): Report attribute error
        raw_response (Any): Report attribute raw_response
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    sector: Any
    response_size: Any
    amplification: Any
    error: Any
    raw_response: Any

class ScanXdmcp:
    '''Representation of report Open-XDMCP with type vulnerable-system and taxonomy vulnerable

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/accessible-xdmcp-service-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        severity (Any): Report attribute severity
        ip (Any): Report attribute ip
        protocol (Any): Report attribute protocol
        port (Any): Report attribute port
        hostname (Any): Report attribute hostname
        tag (Any): Report attribute tag
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        hostname_source (Any): Report attribute hostname_source
        opcode (Any): Report attribute opcode
        reported_hostname (Any): Report attribute reported_hostname
        status (Any): Report attribute status
        response_size (Any): Report attribute response_size
        amplification (Any): Report attribute amplification
        sector (Any): Report attribute sector
    '''
    timestamp: Any
    severity: Any
    ip: Any
    protocol: Any
    port: Any
    hostname: Any
    tag: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    hostname_source: Any
    opcode: Any
    reported_hostname: Any
    status: Any
    response_size: Any
    amplification: Any
    sector: Any

class SpamUrl:
    '''Representation of report Spam-URL with type spam and taxonomy abusive-content

        For more information, visit https://www.shadowserver.org/what-we-do/network-reporting/spam-url-report/
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        url (Any): Report attribute url
        hostname (Any): Report attribute hostname
        ip (Any): Report attribute ip
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        naics (Any): Report attribute naics
        sector (Any): Report attribute sector
        severity (Any): Report attribute severity
        port (Any): Report attribute port
        tag (Any): Report attribute tag
        source (Any): Report attribute source
        sender (Any): Report attribute sender
        subject (Any): Report attribute subject
        src_ip (Any): Report attribute src_ip
        src_asn (Any): Report attribute src_asn
        src_geo (Any): Report attribute src_geo
        src_region (Any): Report attribute src_region
        src_city (Any): Report attribute src_city
        src_naics (Any): Report attribute src_naics
        src_sector (Any): Report attribute src_sector
    '''
    timestamp: Any
    url: Any
    hostname: Any
    ip: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    naics: Any
    sector: Any
    severity: Any
    port: Any
    tag: Any
    source: Any
    sender: Any
    subject: Any
    src_ip: Any
    src_asn: Any
    src_geo: Any
    src_region: Any
    src_city: Any
    src_naics: Any
    src_sector: Any

class Special:
    '''Representation of report Special with type vulnerable-system and taxonomy vulnerable

        For more information, visit unknown
        
    Attributes:
        timestamp (Any): Report attribute timestamp
        ip (Any): Report attribute ip
        port (Any): Report attribute port
        protocol (Any): Report attribute protocol
        asn (Any): Report attribute asn
        geo (Any): Report attribute geo
        region (Any): Report attribute region
        city (Any): Report attribute city
        hostname (Any): Report attribute hostname
        naics (Any): Report attribute naics
        sector (Any): Report attribute sector
        tag (Any): Report attribute tag
        public_source (Any): Report attribute public_source
        status (Any): Report attribute status
        detail (Any): Report attribute detail
        method (Any): Report attribute method
        device_vendor (Any): Report attribute device_vendor
        severity (Any): Report attribute severity
        hostname_source (Any): Report attribute hostname_source
    '''
    timestamp: Any
    ip: Any
    port: Any
    protocol: Any
    asn: Any
    geo: Any
    region: Any
    city: Any
    hostname: Any
    naics: Any
    sector: Any
    tag: Any
    public_source: Any
    status: Any
    detail: Any
    method: Any
    device_vendor: Any
    severity: Any
    hostname_source: Any

