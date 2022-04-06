import cryptid.CryptID;
import cryptid.ibe.IdentityBasedEncryption;
import cryptid.ibe.domain.PrivateKey;

import cryptid.ibe.domain.SecurityLevel;
import cryptid.ibe.exception.SetupException;

import java.math.BigInteger;


//Public wrapper class
public class PKGWrapper {

    //IBE instance used for application
    private IdentityBasedEncryption ibe;
    private BigInteger c;

    //Public constructor
    public PKGWrapper() throws SetupException{
        ibe = CryptID.setupBonehFranklin(SecurityLevel.LOWEST);
    }

    //Return IBE instance
    public IdentityBasedEncryption getInstance(){
        return ibe;
    }

    //Current empty method for decryption
    public PrivateKey getPrivateKey(){

        return ibe.extract("test");
    }

    public BigInteger get_show_protocol_c(){
        //challenge
        this.c = BigInteger.valueOf(800815355);
        return c;
    }

    public void verify_credential_signature(Credential credential, BigInteger a, BigInteger r_1, BigInteger r_2, BigInteger r_3){
        BigInteger p = Utilities.systemParameters.get_p();
        BigInteger g_1 = Utilities.systemParameters.get_g_1();
        BigInteger g_2 = Utilities.systemParameters.get_g_2();
        BigInteger h_0 = Utilities.systemParameters.get_h_0();


        BigInteger h_pow_c = credential.get_brands_show_protocol_public_key().modPow(c, p);
        BigInteger left_side = h_pow_c.multiply(a).mod(p);

        BigInteger g_1_pow_r_1 = g_1.modPow(r_1, p);
        BigInteger g_2_pow_r_2 = g_2.modPow(r_2, p);
        BigInteger h_0_pow_r_3 = h_0.modPow(r_3, p);
        BigInteger right_side = g_1_pow_r_1.multiply(g_2_pow_r_2).multiply(h_0_pow_r_3).mod(p);

        assert left_side.equals(right_side);

        System.out.println("Show Protocol Check passed: " + left_side.equals(right_side));
    }

}
