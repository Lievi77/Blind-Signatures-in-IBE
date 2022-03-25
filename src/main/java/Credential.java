import org.javatuples.Tuple;

import java.math.BigInteger;

public class Credential {

    private final BigInteger alpha_one;

    static int id_count = 0;

    private int id;

    private Tuple ellipticPoint;

    //regular public key is not pow alpha_one
    private BigInteger unblinded_public_key;

    private BigInteger blinded_public_key;

    private String signature;

    private final SystemParameters params; //system parameters

    private final String x_1; // attribute

    private final BigInteger x_1_as_big_int;

    private final String x_2;

    private final BigInteger x_2_as_big_int;

    public Credential(SystemParameters params, String x_1, String x_2, BigInteger alpha_one){
        this.params = params;
        this.x_1 = x_1;
        x_1_as_big_int = Utilities.str_to_big_int(x_1);

        this.x_2 = x_2;
        x_2_as_big_int = Utilities.str_to_big_int(x_2);

        //sanity check
        assert x_1_as_big_int.compareTo(params.get_q()) < 0 :"Must be less than q";

        this.alpha_one = alpha_one;

        this.generate_public_key();

        id++;
    }

    private void generate_public_key(){
        //Generates both normal public and blinded public key

        BigInteger g_1 = params.get_g_1();
        BigInteger g_2 = params.get_g_2();
        BigInteger h_0 = params.get_h_0();
        BigInteger p = params.get_p();


        BigInteger g_one_pow_x_1 = g_1.modPow(x_1_as_big_int,p);
        BigInteger g_two_pow_x_2 = g_2.modPow(x_2_as_big_int, p);
        BigInteger base = g_one_pow_x_1.multiply(g_two_pow_x_2).mod(p);

        //unblinded public key
        this.unblinded_public_key = base.multiply(h_0).mod(p);
        System.out.println("--> Unblinded public key, credential: " + unblinded_public_key);

        //blind public key
        this.blinded_public_key =  unblinded_public_key.modPow(alpha_one,p);
        System.out.println("--> Blinded public key, credential: " + blinded_public_key);

        //important!!
        assert  unblinded_public_key.compareTo(BigInteger.ONE) != 0;
        assert blinded_public_key.compareTo(BigInteger.ONE) != 0;

    }

    public BigInteger get_blinded_public_key(){

        System.out.println("Blinded key was used: " + this.blinded_public_key );
        return this.blinded_public_key;
    }

    public BigInteger get_x1_big_int(){
        return x_1_as_big_int;
    }

    public BigInteger get_x2_big_int() {return x_2_as_big_int; }


    public BigInteger get_unblinded_public_key(){
        System.out.println("Unblinded key was used: " + this.unblinded_public_key);
        return unblinded_public_key; }


    public int getId(){
        return id;
    }



}
