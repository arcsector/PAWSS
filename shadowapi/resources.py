class QueryFilters:
    AGENT = "agent"
    APPLICATION = "application"
    ASN = "asn"
    ASN_NAME = "asn_name"
    BANNER = "banner"
    CITY = "city"
    COUNTY_FIPS = "county_fips"
    COUNTY_NAME = "county_name"
    DEVICE_MODEL = "device_model"
    DEVICE_SECTOR = "device_sector"
    DEVICE_TYPE = "device_type"
    DEVICE_VENDOR = "device_vendor"
    DEVICE_VERSION = "device_version"
    DOMAIN = "domain"
    DST_ASN = "dst_asn"
    DST_ASN_NAME = "dst_asn_name"
    DST_CITY = "dst_city"
    DST_COUNTY_FIPS = "dst_county_fips"
    DST_COUNTY_NAME = "dst_county_name"
    DST_GEO = "dst_geo"
    DST_IP = "dst_ip"
    DST_ISP_NAME = "dst_isp_name"
    DST_LATITUDE = "dst_latitude"
    DST_LONGITUDE = "dst_longitude"
    DST_NAICS = "dst_naics"
    DST_PORT = "dst_port"
    DST_REGION = "dst_region"
    DST_SECTOR = "dst_sector"
    FAMILY = "family"
    GEO = "geo"
    INFECTION = "infection"
    IP = "ip"
    ISP_NAME = "isp_name"
    LATITUDE = "latitude"
    LONGITUDE = "longitude"
    MD5 = "md5"
    NAICS = "naics"
    PORT = "port"
    PROTOCOL = "protocol"
    REFERER = "referer"
    REGION = "region"
    REGISTRAR = "registrar"
    SECTOR = "sector"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    SID = "sid"
    SOURCE = "source"
    SOURCE_URL = "source_url"
    TAG = "tag"
    TEXT = "text"
    TIMESTAMP = "timestamp"
    TLD = "tld"
    TYPE = "type"
    VERSION = "version"

    query_list = [
        "agent",
        "application",
        "asn",
        "asn_name",
        "banner",
        "city",
        "county_fips",
        "county_name",
        "device_model",
        "device_sector",
        "device_type",
        "device_vendor",
        "device_version",
        "domain",
        "dst_asn",
        "dst_asn_name",
        "dst_city",
        "dst_county_fips",
        "dst_county_name",
        "dst_geo",
        "dst_ip",
        "dst_isp_name",
        "dst_latitude",
        "dst_longitude",
        "dst_naics",
        "dst_port",
        "dst_region",
        "dst_sector",
        "family",
        "geo",
        "infection",
        "ip",
        "isp_name",
        "latitude",
        "longitude",
        "md5",
        "naics",
        "port",
        "protocol",
        "referer",
        "region",
        "registrar",
        "sector",
        "sha1",
        "sha256",
        "sha512",
        "sid",
        "source",
        "source_url",
        "tag",
        "text",
        "timestamp",
        "tld",
        "type",
        "version"
    ]

class ReportTypes:
    report_types = [
        "blocklist",
        "botnet_drone",
        "cisco_smart_install",
        "compromised_website",
        "ddos_amplification",
        "drone_brute_force",
        "hp_http_scan",
        "hp_ics_scan",
        "netis_router",
        "scan_adb",
        "scan_afp",
        "scan_ard",
        "scan_chargen",
        "scan_coap",
        "scan_cwmp",
        "scan_db2",
        "scan_ssl_freak",
        "scan_ssl_poodle",
        "scan_telnet",
        "scan_tftp",
        "scan_ubiquiti",
        "scan_vnc",
        "scan_xdmcp",
        "sinkhole_http_drone",
        "spam_url"
    ]

class SSLQuery:
    ssl_query = [
    "algorithm",
    "asn",
    "asn_name",
    "auth_ssl_response",
    "auth_tls_response",
    "available_ciphers",
    "available_compression",
    "available_kex",
    "available_mac",
    "banner",
    "bluekeep_vulnerable",
    "browser_error",
    "browser_trusted",
    "cert_expiration_date",
    "cert_expired",
    "cert_issue_date",
    "cert_length",
    "cert_serial_number",
    "cert_valid",
    "cipher_suite",
    "city",
    "content_length",
    "content_type",
    "county_fips",
    "county_name",
    "cve20190708_vulnerable",
    "device_model",
    "device_sector",
    "device_type",
    "device_vendor",
    "device_version",
    "dss_dsa_public_g",
    "dss_dsa_public_p",
    "dss_dsa_public_q",
    "dss_dsa_public_y",
    "dss_generator",
    "dss_generator_length",
    "dss_prime",
    "dss_prime_length",
    "dss_public_key",
    "dss_public_key_length",
    "ecdsa_curve",
    "ecdsa_curve25519",
    "ecdsa_public_key_b",
    "ecdsa_public_key_gx",
    "ecdsa_public_key_gy",
    "ecdsa_public_key_length",
    "ecdsa_public_key_n",
    "ecdsa_public_key_p",
    "ecdsa_public_key_x",
    "ecdsa_public_key_y",
    "ed25519_cert_public_key_bytes",
    "ed25519_cert_public_key_duration",
    "ed25519_cert_public_key_keyid",
    "ed25519_cert_public_key_nonce",
    "ed25519_cert_public_key_principles",
    "ed25519_cert_public_key_raw",
    "ed25519_cert_public_key_serial",
    "ed25519_cert_public_key_sha256",
    "ed25519_cert_public_key_sig_raw",
    "ed25519_cert_public_key_sigkey_bytes",
    "ed25519_cert_public_key_sigkey_raw",
    "ed25519_cert_public_key_sigkey_sha256",
    "ed25519_cert_public_key_sigkey_value",
    "ed25519_cert_public_key_type_id",
    "ed25519_cert_public_key_type_name",
    "ed25519_cert_public_key_valid_after",
    "ed25519_cert_public_key_valid_before",
    "ed25519_curve25519",
    "freak_cipher_suite",
    "freak_vulnerable",
    "geo",
    "handshake",
    "hostname",
    "http_code",
    "http_connection",
    "http_date",
    "http_info",
    "http_ipv4",
    "http_ipv6",
    "http_name",
    "http_port",
    "http_ptr",
    "http_reason",
    "http_response_type",
    "http_target",
    "ip",
    "isp_name",
    "issuer_business_category",
    "issuer_common_name",
    "issuer_country",
    "issuer_email_address",
    "issuer_given_name",
    "issuer_locality_name",
    "issuer_organization_name",
    "issuer_organization_unit_name",
    "issuer_postal_code",
    "issuer_serialnumber",
    "issuer_state_or_province_name",
    "issuer_street_address",
    "issuer_surname",
    "jarm",
    "key_algorithm",
    "latitude",
    "longitude",
    "md5_fingerprint",
    "mdns_ipv4",
    "mdns_ipv6",
    "mdns_name",
    "naics",
    "port",
    "protocol",
    "public_key_md5",
    "public_key_sha1",
    "public_key_sha256",
    "public_key_sha512",
    "rdp_protocol",
    "region",
    "rsa_exponent",
    "rsa_generator",
    "rsa_generator_length",
    "rsa_length",
    "rsa_modulus",
    "rsa_prime",
    "rsa_prime_length",
    "rsa_public_key",
    "rsa_public_key_length",
    "rsubject_email_address",
    "sector",
    "selected_cipher",
    "selected_compression",
    "selected_kex",
    "selected_mac",
    "self_signed",
    "server_cookie",
    "server_host_key",
    "server_host_key_sha256",
    "server_signature_raw",
    "server_signature_value",
    "server_type",
    "serverid_comment",
    "serverid_raw",
    "serverid_software",
    "serverid_version",
    "services",
    "set_cookie",
    "sha1_fingerprint",
    "sha256_fingerprint",
    "sha512_fingerprint",
    "signature_algorithm",
    "source",
    "ssl_version",
    "sslv3_supported",
    "subject_business_category",
    "subject_common_name",
    "subject_country",
    "subject_email_address",
    "subject_given_name",
    "subject_locality_name",
    "subject_organization_name",
    "subject_organization_unit_name",
    "subject_postal_code",
    "subject_serial_number",
    "subject_state_or_province_name",
    "subject_street_address",
    "subject_surname",
    "sysdesc",
    "sysname",
    "tag",
    "timestamp",
    "tlsv13_cipher",
    "tlsv13_support",
    "transfer_encoding",
    "type",
    "userauth_methods",
    "validation_level",
    "version",
    "workstation_info",
    "workstation_ipv4",
    "workstation_ipv6",
    "workstation_name",
    "www_authenticate"
]