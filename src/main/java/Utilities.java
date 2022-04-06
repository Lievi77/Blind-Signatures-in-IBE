import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Utilities {
    //class of static method
    public static SecureRandom secureRandom = new SecureRandom();

    public static SystemParameters systemParameters;

    private static BigInteger ELEVEN = BigInteger.valueOf(11);
    private static BigInteger TWELVE = BigInteger.valueOf(12);

    public static BigInteger str_to_big_int(String s){
        //Every single SHA-1 output will be in Z_q (q is 161 bits)

        //transform the hex string to a big integer
        String hex_hashed = hash_attribute(s);

        BigInteger hex_as_big_int = new BigInteger(hex_hashed, 16);

        assert hex_as_big_int.compareTo(BigInteger.ZERO) > 0 : "Must be within Z_Q";

       return hex_as_big_int;

    }

    public static String hash_attribute(String s){
         try{
             MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

             //sanity check
             sha1.reset();

             sha1.update(s.getBytes());
            byte [] hash  = sha1.digest();
            //hash = reduced_byte_count(hash);

             return Hex.toHexString(hash);

         }catch(NoSuchAlgorithmException e){
             System.out.println("Error, setting output to NULL");
             return "NULL";
         }
    }

    public static void setSystemParameters(CA ca){
        Utilities.systemParameters = ca.get_system_parameters();
    }

    public static BigInteger get_generator(int number_of_bits) {
        BigInteger q;
        BigInteger p;

        do {
            q = BigInteger.probablePrime(number_of_bits, new SecureRandom()); //

            p = q.multiply(BigInteger.TWO.pow(1024 - number_of_bits)); // get 1024 bit p (1024 - number_of_bits)

            p = p.add(BigInteger.ONE);

        } while (!p.isProbablePrime(10) || !q.mod(TWELVE).equals(ELEVEN) );

        System.out.println(q.bitLength() + " Prime q: " + q);
        System.out.println(p.bitLength() + " Prime p: " + p);

        assert q.isProbablePrime(100) : "must be a prime";
        assert q.mod(TWELVE).equals(ELEVEN) : "Must be congruent 11 modulo 12";
        assert p.isProbablePrime(100) : "must be prime";
        assert p.subtract(BigInteger.ONE).mod(q).equals(BigInteger.ZERO); // ensures p-1 is divisible by q
        assert p.bitLength() == 1024;

        BigInteger h = new BigInteger(160, new SecureRandom());

        assert h.compareTo(BigInteger.ONE) > 0 : "H has to be greater than 1";

        BigInteger exp = p.subtract(BigInteger.ONE).divide(q);

        BigInteger g = h.modPow(exp, p);

        assert g.compareTo(BigInteger.ONE) > 0 : "G CANNOT BE ONE";

        System.out.println("Generator g_0: " + g);

        return g;
    }

}
