import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class Hashing {
    
    public static String PBKDF2Hash(String stringToHash, Integer iterations, Integer numBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecureRandom randomGenerator = new SecureRandom();
        byte[] salt = new byte[16];
        randomGenerator.nextBytes(salt);
        PBEKeySpec PBEKeySpec = new PBEKeySpec(stringToHash.toCharArray(), salt, iterations, 8*numBytes);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = secretKeyFactory.generateSecret(PBEKeySpec).getEncoded();
        return iterations + ":" + byteToHex(salt) + ":" + byteToHex(hash);
    }

    public static Boolean PBKDF2HashMatch(String string, String hashedString) throws NoSuchAlgorithmException, InvalidKeySpecException {

        String[] hashSections = hashedString.split(":");
        Integer numIterations = Integer.parseInt(hashSections[0]);
        byte[] salt = hexToByte(hashSections[1]);
        byte[] hash = hexToByte(hashSections[2]);


        PBEKeySpec keySpec = new PBEKeySpec(string.toCharArray(),salt, numIterations, hash.length * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] testHash = skf.generateSecret(keySpec).getEncoded();

        int difference = hash.length ^ testHash.length;
        for(int i = 0; i < hash.length && i < testHash.length; i++){ difference |= hash[i] ^ testHash[i]; }
        return difference == 0;
    }
    private static String byteToHex(byte[] array) {

        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);

        Integer length = array.length*2 - hex.length();

        if(length > 0) return String.format("%0" + length + "d", 0) + hex;

        else return hex;
    }

    private static byte[] hexToByte(String hex){
        byte[] bytes = new byte[hex.length()/2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        }

        return bytes;
    }



}
