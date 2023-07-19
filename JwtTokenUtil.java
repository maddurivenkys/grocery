import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

public class JwtTokenUtil {

    // This value should point to the location of your PEM-encoded private key
    private static final String PRIVATE_KEY_PATH = "/path/to/your-private-key.pem";

    private static PrivateKey getPrivateKey() {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            ClassLoader classLoader = JwtTokenUtil.class.getClassLoader();
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(classLoader.getResourceAsStream(PRIVATE_KEY_PATH));
            return (PrivateKey) certificate.getPrivateKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load private key certificate.", e);
        }
    }

    public static String createToken(String subject, long expirationMillis) {
        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + expirationMillis);

        Key key = Keys.hmacShaKeyFor(getPrivateKey().getEncoded());

        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public static String extractSubject(String token) {
        Key key = Keys.hmacShaKeyFor(getPrivateKey().getEncoded());

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public static boolean isTokenValid(String token) {
        try {
            Key key = Keys.hmacShaKeyFor(getPrivateKey().getEncoded());
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
