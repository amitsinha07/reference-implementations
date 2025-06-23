import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class KeyGeneratorFixed {
    
    public static Map<String, String> generateKeyPairs() throws Exception {
        // Generate Ed25519 signing key pair
        KeyPairGenerator signingKeyGen = KeyPairGenerator.getInstance("Ed25519");
        KeyPair signingKeyPair = signingKeyGen.generateKeyPair();
        
        // Generate X25519 encryption key pair  
        KeyPairGenerator encryptionKeyGen = KeyPairGenerator.getInstance("X25519");
        KeyPair encryptionKeyPair = encryptionKeyGen.generateKeyPair();
        
        // Extract raw key material for signing keys (to match TweetNaCl format)
        byte[] signingPrivateEncoded = signingKeyPair.getPrivate().getEncoded();
        byte[] signingPublicEncoded = signingKeyPair.getPublic().getEncoded();
        
        // For Ed25519, extract the raw 32-byte private key and 32-byte public key
        // The PKCS#8 format has overhead, we need to extract just the key material
        byte[] signingPrivateRaw = extractEd25519PrivateKey(signingPrivateEncoded);
        byte[] signingPublicRaw = extractEd25519PublicKey(signingPublicEncoded);
        
        // Create 64-byte signing private key (32 bytes private + 32 bytes public, like TweetNaCl)
        byte[] signingPrivateKey64 = new byte[64];
        System.arraycopy(signingPrivateRaw, 0, signingPrivateKey64, 0, 32);
        System.arraycopy(signingPublicRaw, 0, signingPrivateKey64, 32, 32);
        
        // Get encryption keys in encoded format (matching Node.js crypto behavior)
        byte[] encryptionPrivateBytes = encryptionKeyPair.getPrivate().getEncoded();
        byte[] encryptionPublicBytes = encryptionKeyPair.getPublic().getEncoded();
        
        // Convert to Base64 strings
        String signingPrivateKey = Base64.getEncoder().encodeToString(signingPrivateKey64);
        String signingPublicKey = Base64.getEncoder().encodeToString(signingPublicRaw);
        String encryptionPrivateKey = Base64.getEncoder().encodeToString(encryptionPrivateBytes);
        String encryptionPublicKey = Base64.getEncoder().encodeToString(encryptionPublicBytes);
        
        // Create result map matching Node.js output format
        Map<String, String> result = new HashMap<>();
        result.put("Signing_private_key", signingPrivateKey);
        result.put("Signing_public_key", signingPublicKey);
        result.put("Encryption_Privatekey", encryptionPrivateKey);
        result.put("Encryption_Publickey", encryptionPublicKey);
        
        return result;
    }
    
    private static byte[] extractEd25519PrivateKey(byte[] pkcs8Encoded) {
        // PKCS#8 format for Ed25519: the last 32 bytes are the private key
        // Skip the ASN.1 overhead and extract raw 32-byte private key
        return Arrays.copyOfRange(pkcs8Encoded, pkcs8Encoded.length - 32, pkcs8Encoded.length);
    }
    
    private static byte[] extractEd25519PublicKey(byte[] x509Encoded) {
        // X.509 format for Ed25519: the last 32 bytes are the public key
        // Skip the ASN.1 overhead and extract raw 32-byte public key
        return Arrays.copyOfRange(x509Encoded, x509Encoded.length - 32, x509Encoded.length);
    }
    
    public static void main(String[] args) {
        try {
            Map<String, String> keyPairs = generateKeyPairs();
            
            // Print in exactly the same format as Node.js
            System.out.println("{");
            System.out.println("  Signing_private_key: '" + keyPairs.get("Signing_private_key") + "',");
            System.out.println("  Signing_public_key: '" + keyPairs.get("Signing_public_key") + "',");
            System.out.println("  Encryption_Privatekey: '" + keyPairs.get("Encryption_Privatekey") + "',");
            System.out.println("  Encryption_Publickey: '" + keyPairs.get("Encryption_Publickey") + "'");
            System.out.println("}");
            
        } catch (Exception e) {
            System.err.println("Error generating key pairs: " + e.getMessage());
            e.printStackTrace();
        }
    }
} 