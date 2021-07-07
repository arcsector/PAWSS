class QueryFilters:
    """Query Filters for Reports"""

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
    """Report Types for query validation"""

    BLOCKLIST = "blocklist"
    BOTNET_DRONE = "botnet_drone"
    CISCO_SMART_INSTALL = "cisco_smart_install"
    COMPROMISED_WEBSITE = "compromised_website"
    DDOS_AMPLIFICATION = "ddos_amplification"
    DRONE_BRUTE_FORCE = "drone_brute_force"
    HP_HTTP_SCAN = "hp_http_scan"
    HP_ICS_SCAN = "hp_ics_scan"
    NETIS_ROUTER = "netis_router"
    SCAN_ADB = "scan_adb"
    SCAN_AFP = "scan_afp"
    SCAN_ARD = "scan_ard"
    SCAN_CHARGEN = "scan_chargen"
    SCAN_COAP = "scan_coap"
    SCAN_CWMP = "scan_cwmp"
    SCAN_DB2 = "scan_db2"
    SCAN_SSL_FREAK = "scan_ssl_freak"
    SCAN_SSL_POODLE = "scan_ssl_poodle"
    SCAN_TELNET = "scan_telnet"
    SCAN_TFTP = "scan_tftp"
    SCAN_UBIQUITI = "scan_ubiquiti"
    SCAN_VNC = "scan_vnc"
    SCAN_XDMCP = "scan_xdmcp"
    SINKHOLE_HTTP_DRONE = "sinkhole_http_drone"
    SPAM_URL = "spam_url"

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
    """SSL Query parameters and filters"""

    ALGORITHM = "algorithm"
    ASN = "asn"
    ASN_NAME = "asn_name"
    AUTH_SSL_RESPONSE = "auth_ssl_response"
    AUTH_TLS_RESPONSE = "auth_tls_response"
    AVAILABLE_CIPHERS = "available_ciphers"
    AVAILABLE_COMPRESSION = "available_compression"
    AVAILABLE_KEX = "available_kex"
    AVAILABLE_MAC = "available_mac"
    BANNER = "banner"
    BLUEKEEP_VULNERABLE = "bluekeep_vulnerable"
    BROWSER_ERROR = "browser_error"
    BROWSER_TRUSTED = "browser_trusted"
    CERT_EXPIRATION_DATE = "cert_expiration_date"
    CERT_EXPIRED = "cert_expired"
    CERT_ISSUE_DATE = "cert_issue_date"
    CERT_LENGTH = "cert_length"
    CERT_SERIAL_NUMBER = "cert_serial_number"
    CERT_VALID = "cert_valid"
    CIPHER_SUITE = "cipher_suite"
    CITY = "city"
    CONTENT_LENGTH = "content_length"
    CONTENT_TYPE = "content_type"
    COUNTY_FIPS = "county_fips"
    COUNTY_NAME = "county_name"
    CVE20190708_VULNERABLE = "cve20190708_vulnerable"
    DEVICE_MODEL = "device_model"
    DEVICE_SECTOR = "device_sector"
    DEVICE_TYPE = "device_type"
    DEVICE_VENDOR = "device_vendor"
    DEVICE_VERSION = "device_version"
    DSS_DSA_PUBLIC_G = "dss_dsa_public_g"
    DSS_DSA_PUBLIC_P = "dss_dsa_public_p"
    DSS_DSA_PUBLIC_Q = "dss_dsa_public_q"
    DSS_DSA_PUBLIC_Y = "dss_dsa_public_y"
    DSS_GENERATOR = "dss_generator"
    DSS_GENERATOR_LENGTH = "dss_generator_length"
    DSS_PRIME = "dss_prime"
    DSS_PRIME_LENGTH = "dss_prime_length"
    DSS_PUBLIC_KEY = "dss_public_key"
    DSS_PUBLIC_KEY_LENGTH = "dss_public_key_length"
    ECDSA_CURVE = "ecdsa_curve"
    ECDSA_CURVE25519 = "ecdsa_curve25519"
    ECDSA_PUBLIC_KEY_B = "ecdsa_public_key_b"
    ECDSA_PUBLIC_KEY_GX = "ecdsa_public_key_gx"
    ECDSA_PUBLIC_KEY_GY = "ecdsa_public_key_gy"
    ECDSA_PUBLIC_KEY_LENGTH = "ecdsa_public_key_length"
    ECDSA_PUBLIC_KEY_N = "ecdsa_public_key_n"
    ECDSA_PUBLIC_KEY_P = "ecdsa_public_key_p"
    ECDSA_PUBLIC_KEY_X = "ecdsa_public_key_x"
    ECDSA_PUBLIC_KEY_Y = "ecdsa_public_key_y"
    ED25519_CERT_PUBLIC_KEY_BYTES = "ed25519_cert_public_key_bytes"
    ED25519_CERT_PUBLIC_KEY_DURATION = "ed25519_cert_public_key_duration"
    ED25519_CERT_PUBLIC_KEY_KEYID = "ed25519_cert_public_key_keyid"
    ED25519_CERT_PUBLIC_KEY_NONCE = "ed25519_cert_public_key_nonce"
    ED25519_CERT_PUBLIC_KEY_PRINCIPLES = "ed25519_cert_public_key_principles"
    ED25519_CERT_PUBLIC_KEY_RAW = "ed25519_cert_public_key_raw"
    ED25519_CERT_PUBLIC_KEY_SERIAL = "ed25519_cert_public_key_serial"
    ED25519_CERT_PUBLIC_KEY_SHA256 = "ed25519_cert_public_key_sha256"
    ED25519_CERT_PUBLIC_KEY_SIG_RAW = "ed25519_cert_public_key_sig_raw"
    ED25519_CERT_PUBLIC_KEY_SIGKEY_BYTES = "ed25519_cert_public_key_sigkey_bytes"
    ED25519_CERT_PUBLIC_KEY_SIGKEY_RAW = "ed25519_cert_public_key_sigkey_raw"
    ED25519_CERT_PUBLIC_KEY_SIGKEY_SHA256 = "ed25519_cert_public_key_sigkey_sha256"
    ED25519_CERT_PUBLIC_KEY_SIGKEY_VALUE = "ed25519_cert_public_key_sigkey_value"
    ED25519_CERT_PUBLIC_KEY_TYPE_ID = "ed25519_cert_public_key_type_id"
    ED25519_CERT_PUBLIC_KEY_TYPE_NAME = "ed25519_cert_public_key_type_name"
    ED25519_CERT_PUBLIC_KEY_VALID_AFTER = "ed25519_cert_public_key_valid_after"
    ED25519_CERT_PUBLIC_KEY_VALID_BEFORE = "ed25519_cert_public_key_valid_before"
    ED25519_CURVE25519 = "ed25519_curve25519"
    FREAK_CIPHER_SUITE = "freak_cipher_suite"
    FREAK_VULNERABLE = "freak_vulnerable"
    GEO = "geo"
    HANDSHAKE = "handshake"
    HOSTNAME = "hostname"
    HTTP_CODE = "http_code"
    HTTP_CONNECTION = "http_connection"
    HTTP_DATE = "http_date"
    HTTP_INFO = "http_info"
    HTTP_IPV4 = "http_ipv4"
    HTTP_IPV6 = "http_ipv6"
    HTTP_NAME = "http_name"
    HTTP_PORT = "http_port"
    HTTP_PTR = "http_ptr"
    HTTP_REASON = "http_reason"
    HTTP_RESPONSE_TYPE = "http_response_type"
    HTTP_TARGET = "http_target"
    IP = "ip"
    ISP_NAME = "isp_name"
    ISSUER_BUSINESS_CATEGORY = "issuer_business_category"
    ISSUER_COMMON_NAME = "issuer_common_name"
    ISSUER_COUNTRY = "issuer_country"
    ISSUER_EMAIL_ADDRESS = "issuer_email_address"
    ISSUER_GIVEN_NAME = "issuer_given_name"
    ISSUER_LOCALITY_NAME = "issuer_locality_name"
    ISSUER_ORGANIZATION_NAME = "issuer_organization_name"
    ISSUER_ORGANIZATION_UNIT_NAME = "issuer_organization_unit_name"
    ISSUER_POSTAL_CODE = "issuer_postal_code"
    ISSUER_SERIALNUMBER = "issuer_serialnumber"
    ISSUER_STATE_OR_PROVINCE_NAME = "issuer_state_or_province_name"
    ISSUER_STREET_ADDRESS = "issuer_street_address"
    ISSUER_SURNAME = "issuer_surname"
    JARM = "jarm"
    KEY_ALGORITHM = "key_algorithm"
    LATITUDE = "latitude"
    LONGITUDE = "longitude"
    MD5_FINGERPRINT = "md5_fingerprint"
    MDNS_IPV4 = "mdns_ipv4"
    MDNS_IPV6 = "mdns_ipv6"
    MDNS_NAME = "mdns_name"
    NAICS = "naics"
    PORT = "port"
    PROTOCOL = "protocol"
    PUBLIC_KEY_MD5 = "public_key_md5"
    PUBLIC_KEY_SHA1 = "public_key_sha1"
    PUBLIC_KEY_SHA256 = "public_key_sha256"
    PUBLIC_KEY_SHA512 = "public_key_sha512"
    RDP_PROTOCOL = "rdp_protocol"
    REGION = "region"
    RSA_EXPONENT = "rsa_exponent"
    RSA_GENERATOR = "rsa_generator"
    RSA_GENERATOR_LENGTH = "rsa_generator_length"
    RSA_LENGTH = "rsa_length"
    RSA_MODULUS = "rsa_modulus"
    RSA_PRIME = "rsa_prime"
    RSA_PRIME_LENGTH = "rsa_prime_length"
    RSA_PUBLIC_KEY = "rsa_public_key"
    RSA_PUBLIC_KEY_LENGTH = "rsa_public_key_length"
    RSUBJECT_EMAIL_ADDRESS = "rsubject_email_address"
    SECTOR = "sector"
    SELECTED_CIPHER = "selected_cipher"
    SELECTED_COMPRESSION = "selected_compression"
    SELECTED_KEX = "selected_kex"
    SELECTED_MAC = "selected_mac"
    SELF_SIGNED = "self_signed"
    SERVER_COOKIE = "server_cookie"
    SERVER_HOST_KEY = "server_host_key"
    SERVER_HOST_KEY_SHA256 = "server_host_key_sha256"
    SERVER_SIGNATURE_RAW = "server_signature_raw"
    SERVER_SIGNATURE_VALUE = "server_signature_value"
    SERVER_TYPE = "server_type"
    SERVERID_COMMENT = "serverid_comment"
    SERVERID_RAW = "serverid_raw"
    SERVERID_SOFTWARE = "serverid_software"
    SERVERID_VERSION = "serverid_version"
    SERVICES = "services"
    SET_COOKIE = "set_cookie"
    SHA1_FINGERPRINT = "sha1_fingerprint"
    SHA256_FINGERPRINT = "sha256_fingerprint"
    SHA512_FINGERPRINT = "sha512_fingerprint"
    SIGNATURE_ALGORITHM = "signature_algorithm"
    SOURCE = "source"
    SSL_VERSION = "ssl_version"
    SSLV3_SUPPORTED = "sslv3_supported"
    SUBJECT_BUSINESS_CATEGORY = "subject_business_category"
    SUBJECT_COMMON_NAME = "subject_common_name"
    SUBJECT_COUNTRY = "subject_country"
    SUBJECT_EMAIL_ADDRESS = "subject_email_address"
    SUBJECT_GIVEN_NAME = "subject_given_name"
    SUBJECT_LOCALITY_NAME = "subject_locality_name"
    SUBJECT_ORGANIZATION_NAME = "subject_organization_name"
    SUBJECT_ORGANIZATION_UNIT_NAME = "subject_organization_unit_name"
    SUBJECT_POSTAL_CODE = "subject_postal_code"
    SUBJECT_SERIAL_NUMBER = "subject_serial_number"
    SUBJECT_STATE_OR_PROVINCE_NAME = "subject_state_or_province_name"
    SUBJECT_STREET_ADDRESS = "subject_street_address"
    SUBJECT_SURNAME = "subject_surname"
    SYSDESC = "sysdesc"
    SYSNAME = "sysname"
    TAG = "tag"
    TIMESTAMP = "timestamp"
    TLSV13_CIPHER = "tlsv13_cipher"
    TLSV13_SUPPORT = "tlsv13_support"
    TRANSFER_ENCODING = "transfer_encoding"
    TYPE = "type"
    USERAUTH_METHODS = "userauth_methods"
    VALIDATION_LEVEL = "validation_level"
    VERSION = "version"
    WORKSTATION_INFO = "workstation_info"
    WORKSTATION_IPV4 = "workstation_ipv4"
    WORKSTATION_IPV6 = "workstation_ipv6"
    WORKSTATION_NAME = "workstation_name"
    WWW_AUTHENTICATE = "www_authenticate"

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