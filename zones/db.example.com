$TTL 300
$ORIGIN example.com.
@   IN SOA dns.example.com. hostmaster.example.com. (2025110601 3600 900 1209600 300)
    IN NS dns.example.com.
dns IN A 10.0.0.53
mx  IN A 10.0.0.25
@   IN MX 10 mx.example.com.
@   IN TXT "v=spf1 a mx -all"
_dmarc IN TXT "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com"
