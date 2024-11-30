import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class AESKeyGenerator {

    public static void main(String[] args) {
        try {
            // Generate a 256-bit AES key
            SecretKey secretKey = generateAESKey(256);
            
            // Get the key as a byte array
            byte[] keyBytes = secretKey.getEncoded();
            
            // Print the key in C++ format
            System.out.println(formatKeyForCPP(keyBytes));
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    /**
     * Generates a strong AES key with the specified size.
     *
     * @param keySize The size of the AES key (e.g., 128, 192, or 256 bits).
     * @return A SecretKey object representing the AES key.
     * @throws NoSuchAlgorithmException If AES algorithm is not available.
     */
    public static SecretKey generateAESKey(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        keyGen.init(keySize, secureRandom);
        return keyGen.generateKey();
    }

    /**
     * Formats a byte array as a C++ unsigned char array.
     *
     * @param bytes The byte array to format.
     * @return A string representation of the array in C++ format.
     */
    public static String formatKeyForCPP(byte[] bytes) {
        StringBuilder cppFormat = new StringBuilder();
        cppFormat.append("const unsigned char AES_KEY[")
                .append(bytes.length)
                .append("] = { ");
        
        for (int i = 0; i < bytes.length; i++) {
            // Convert each byte to a two-digit hexadecimal value
            cppFormat.append(String.format("0x%02x", bytes[i] & 0xFF));
            
            // Add a comma after each byte, except the last
            if (i < bytes.length - 1) {
                cppFormat.append(", ");
            }
            
            // Break into multiple lines for readability
            if ((i + 1) % 8 == 0) {
                cppFormat.append("\n    ");
            }
        }
        cppFormat.append(" };");
        return cppFormat.toString();
    }
}
