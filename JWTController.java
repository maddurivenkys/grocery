@RestController
public class JwtController {

    @GetMapping("/generateToken")
    public ResponseEntity<String> generateToken() {
        // Set the subject and token expiration time in milliseconds (e.g., 1 hour)
        String token = JwtTokenUtil.createToken("your-username", 3600000);
        return ResponseEntity.ok(token);
    }

    @GetMapping("/validateToken")
    public ResponseEntity<String> validateToken(@RequestParam String token) {
        boolean isValid = JwtTokenUtil.isTokenValid(token);

        if (isValid) {
            String subject = JwtTokenUtil.extractSubject(token);
            return ResponseEntity.ok("Valid token for user: " + subject);
        } else {
            return ResponseEntity.badRequest().body("Invalid token.");
        }
    }
}
