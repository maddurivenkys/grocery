@RestController
@RequestMapping("/api/public")
public class PublicController {

    @GetMapping
    public ResponseEntity<String> getPublicData() {
        return ResponseEntity.ok("This is public data!");
    }
}

@RestController
@RequestMapping("/api/private")
public class PrivateController {

    @GetMapping
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<String> getPrivateData() {
        return ResponseEntity.ok("This is private data!");
    }
}
