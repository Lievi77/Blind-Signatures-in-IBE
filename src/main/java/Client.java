import cryptid.ibe.IdentityBasedEncryption;
import cryptid.ibe.domain.CipherTextTuple;

import java.math.BigInteger;
import java.util.Scanner;

public class Client{

    public Scanner inputScanner;
    private final String email;
    private Credential credential;
    private SystemParameters sys_params;


    public Client(String email){
        this.email = email;
        this.inputScanner = new Scanner(System.in);
    }

    public String getEmail(){
        return email;
    }

    public void setSystemParameters(SystemParameters params){
        this.sys_params = params;
    }

    //getter
    private Credential getCredential(){
        return credential;
    }

    //this method sets a new credential for the client
    public void requestCredential(CA admin)  {

        BigInteger q = sys_params.get_q();

        //following the diagram
        BigInteger a_zero = admin.generate_a_zero();

        //first, alice needs to choose 3 different numbers
        BigInteger alpha_one, alpha_two , alpha_three;

        //hardcoded "random"
        //Example of programming with assertion
        alpha_one = BigInteger.valueOf(89); //blinding factor
        System.out.println("Alpha_1 (blinding factor) : " + alpha_one);
        assert alpha_one.compareTo(q) < 0: "Value needs to be less than q";
        assert  alpha_one.gcd(q).equals(BigInteger.ONE);

        alpha_two = BigInteger.valueOf(890);
        System.out.println("Alpha_two: " + alpha_two);
        assert alpha_two.compareTo(q) < 0 : "Value needs to be less than q";

        alpha_three = BigInteger.valueOf(233);
        System.out.println("Alpha_three: " +  alpha_three);
        assert alpha_three.compareTo(q) < 0 : "Value needs to be less than q";

        //create credential
        credential = new Credential(sys_params,email, null, alpha_one);
        //to get h,as in the protocol , call credential.get_blinded_public_key

        BigInteger c_prime_zero = this.generate_c_prime_zero(alpha_two, alpha_three, a_zero);

        assert c_prime_zero.compareTo(q) < 0 : "Value needs to be less than q";

        BigInteger c_zero = (c_prime_zero.subtract(alpha_two)).mod(q);

        assert c_prime_zero.compareTo(q) < 0 : "Value needs to be less than q";

        System.out.println("c_prime_zero: " + c_prime_zero);
        System.out.println("c_zero: "  + c_zero);

        //now, send c_zero to CA
        BigInteger r_zero = admin.generate_r_zero(c_zero, credential.get_x1_big_int());

        System.out.println("r_zero: " + r_zero);

        boolean isValid = this.verify_signature(a_zero,r_zero, c_zero);

        if(isValid){
            //create r'_zero
            System.out.println("Check passed");

            BigInteger numerator = r_zero.add(alpha_three).mod(q);
            BigInteger denominator = alpha_one.modInverse(q);
            BigInteger r_prime_zero = numerator.multiply(denominator).mod(q);

        }else{
            System.out.println("Error!!!");

        }

    }

    private boolean verify_signature(BigInteger a_zero, BigInteger r_zero, BigInteger c_zero) {
        BigInteger g_0 = sys_params.get_g_0();
        BigInteger p = sys_params.get_p();

        BigInteger g_zero_pow_c_zero = g_0.modPow(c_zero,p);

        BigInteger pow_r_zero = credential.get_unblinded_public_key().modPow(r_zero,p);

        BigInteger may_be_a_zero = g_zero_pow_c_zero.multiply(pow_r_zero).mod(p);

        System.out.println("--> a_zero "+a_zero + " ?= " + "funky_part " + may_be_a_zero);

        //assert a_zero.equals(may_be_a_zero) : "Verification of r_0 failed";

        return a_zero.compareTo(may_be_a_zero) == 0;
    }

    private BigInteger generate_c_prime_zero(BigInteger alpha_two, BigInteger alpha_three, BigInteger a_zero)  {

        BigInteger q = sys_params.get_q();
        BigInteger h = this.credential.get_blinded_public_key();
        BigInteger g_0 = sys_params.get_g_0();
        BigInteger p = sys_params.get_p();

        BigInteger g_zero_pow_alpha_two = g_0.modPow(alpha_two,p);
        BigInteger middle_part = credential.get_unblinded_public_key().modPow(alpha_three,p);
        BigInteger alongside = g_zero_pow_alpha_two.multiply(middle_part).multiply(a_zero).mod(p);

        String text = h.toString() + alongside;

        String  hex_hashed_big_int = Utilities.hash_attribute(text);

        BigInteger hex_hashed_as_big_int = new BigInteger(hex_hashed_big_int, 16);

        assert hex_hashed_as_big_int.compareTo(q) < 0 : "Must be less than q";
        assert hex_hashed_as_big_int.compareTo(BigInteger.ZERO) > 0 : "Must be within Z_Q";

        return hex_hashed_as_big_int;
    }

    public CipherTextTuple encryptMessage(IdentityBasedEncryption ibe){
        String plaintext = getPlainText();
        String publicKey = getPublicKey();

        CipherTextTuple cipherText = ibe.encrypt(plaintext,publicKey);

        return cipherText;
    }

    public String getPlainText(){
        System.out.println("Input plaintext to be encrypted below:");
        String plaintext = inputScanner.nextLine();

        return plaintext;
    }

    public String getPublicKey(){
        System.out.println("Input the user's public key for encryption below: ");
        String publicKey = inputScanner.nextLine();

        return publicKey;
    }
}
