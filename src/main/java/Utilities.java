import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utilities {
    //class of static method

    public static BigInteger str_to_big_int(String s){
        //Every single SHA-1 output will be in Z_q (q is 161 bits)

        //transform the hex string to a big integer

        String hex_hashed = hash_attribute(s);

        BigInteger hex_as_big_int = new BigInteger(hex_hashed, 16);
        System.out.println("Hased value as big int: " + hex_as_big_int);

        assert hex_as_big_int.compareTo(BigInteger.ZERO) > 0 : "Must be within Z_Q";

       return hex_as_big_int;

    }

    public static String hash_attribute(String s){
         try{
             System.out.println("~~String to hash: " + s);
             MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

             //sanity check
             sha1.reset();

             sha1.update(s.getBytes());
            byte [] hash  = sha1.digest();
            //hash = reduced_byte_count(hash);

            String value = Hex.toHexString(hash);
            System.out.println("~~Hashed value in hex:" + value);

            return value;

         }catch(NoSuchAlgorithmException e){
             System.out.println("Error, setting output to NULL");
             return "NULL";
         }
    }

}
