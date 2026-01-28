class Config:
    # Network Timeouts in seconds
    SOCKET_TIMEOUT = 5.0
    HTTP_TIMEOUT = 10.0
    DNS_TIMEOUT = 5.0
    
    # Rate Limiting
    DEFAULT_RATE_LIMIT = "5/minute"

settings = Config()
