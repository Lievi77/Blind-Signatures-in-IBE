import java.math.BigInteger;

public class Credential {

    private final BigInteger alpha_one; //blinding factor

    static int id_count = 0;

    private int id;

    //regular public key is not pow alpha_one
    private BigInteger unblinded_public_key;

    private BigInteger blinded_public_key;

    private BigInteger show_protocol_brands_public_key;

    private final SystemParameters system_parameters; //system parameters

    private final String x_1; // attribute

    private final BigInteger x_1_as_big_int;

    private final String x_2; //attribute 2

    private final BigInteger x_2_as_big_int;

    //Credential Signature issued by CA
    private BigInteger c_prime_zero = null; //non-null only after issue protocol is run
    private BigInteger r_prime_zero =  null;

    public Credential(SystemParameters params, String x_1, String x_2, BigInteger alpha_one){
        this.system_parameters = params;
        this.x_1 = x_1;
        x_1_as_big_int = Utilities.str_to_big_int(x_1);

        this.x_2 = x_2;
        x_2_as_big_int = Utilities.str_to_big_int(x_2);

        this.alpha_one = alpha_one;

        this.generate_public_keys();

        id++;
    }

    private void generate_public_keys(){
        //Generates both normal public and blinded public key

        BigInteger g_1 = system_parameters.get_g_1();
        BigInteger g_2 = system_parameters.get_g_2();
        BigInteger h_0 = system_parameters.get_h_0();
        BigInteger p = system_parameters.get_p();


        BigInteger g_one_pow_x_1 = g_1.modPow(x_1_as_big_int,p);
        BigInteger g_two_pow_x_2 = g_2.modPow(x_2_as_big_int, p);
        BigInteger h_0_pow_alpha = h_0.modPow(alpha_one,p);
        BigInteger base = g_one_pow_x_1.multiply(g_two_pow_x_2).mod(p);


        //unblinded public key
        this.unblinded_public_key = base.multiply(h_0).mod(p);
        //System.out.println("--> Unblinded public key, credential: " + unblinded_public_key);

        //blind public key
        this.blinded_public_key =  unblinded_public_key.modPow(alpha_one,p);
        //System.out.println("--> Blinded public key, credential: " + blinded_public_key);

        this.show_protocol_brands_public_key = g_one_pow_x_1.multiply(g_two_pow_x_2).multiply(h_0_pow_alpha).mod(p);

        //important!!
        assert  unblinded_public_key.compareTo(BigInteger.ONE) != 0;
        assert blinded_public_key.compareTo(BigInteger.ONE) != 0;

    }

    public BigInteger get_blinded_public_key(){ return this.blinded_public_key;}

    public BigInteger get_x1_big_int(){
        return x_1_as_big_int;
    }

    public BigInteger get_x2_big_int() {return x_2_as_big_int; }

    public BigInteger get_alpha_one(){return alpha_one;}

    public BigInteger get_unblinded_public_key(){return unblinded_public_key; }

    public BigInteger get_brands_show_protocol_public_key(){return show_protocol_brands_public_key;}

    public int getId(){
        return id;
    }

    public void setSignature(BigInteger c_prime_zero, BigInteger r_prime_zero){
        this.c_prime_zero = c_prime_zero;
        this.r_prime_zero = r_prime_zero;
    }



    public void printSignature(){
        System.out.println("c'0: " +  c_prime_zero);
        System.out.println("r'0: " + r_prime_zero);
    }

}
