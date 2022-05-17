import java.math.BigInteger;

public class Credential {

    private final BigInteger alpha_one; // blinding factor

    // regular public key is not power alpha_one
    private BigInteger unblinded_public_key;

    private BigInteger blinded_public_key;

    private BigInteger show_protocol_brands_public_key;

    private final SystemParameters system_parameters; // system parameters

    private final String x_1; // attribute

    private final BigInteger x_1_as_big_int;

    private final String x_2; // attribute 2

    private final BigInteger x_2_as_big_int;

    private BigInteger blinding;

    // Credential Signature issued by CA
    private BigInteger c_prime_zero = null; // non-null only after issue protocol is run

    private BigInteger r_prime_zero = null;

    /**
     * Constructor for a Brand's Digital Credential according to Issue Protocol.
     * 
     * @param system_parameters the system-wide parameters
     * @param x_1               attribute 1 to be encoded
     * @param x_2               attribute 2 to be encoded
     * @param alpha_one         blinding factor according to Brand's igital
     *                          redential Issue Protocol.
     */
    public Credential(SystemParameters system_parameters, String x_1, String x_2, BigInteger alpha_one) {
        this.system_parameters = system_parameters;

        this.blinding = BigInteger.ONE;

        this.x_1 = x_1;
        x_1_as_big_int = Utilities.str_to_big_int(x_1).multiply(blinding);

        this.x_2 = x_2;
        x_2_as_big_int = Utilities.str_to_big_int(x_2).multiply(blinding);

        this.alpha_one = alpha_one.multiply(blinding);

        this.generate_public_keys();

        id++;
    }

    /**
     * Alternate constructor for blinded credential.
     * 
     * @param system_parameters the system-wide parameters
     * @param x_1               attribute 1 to be encoded
     * @param x_2               attribute 2 to be encoded
     * @param alpha_one         blinding factor according to Brand's igital
     *                          redential Issue Protocol.
     * @param blinding          the blinding factor used to blind either x_1 or x_2
     */
    public Credential(SystemParameters system_parameters, String x_1, String x_2, BigInteger alpha_one,
            BigInteger blinding) {
        this.system_parameters = system_parameters;

        this.blinding = blinding;

        this.x_1 = x_1;
        x_1_as_big_int = Utilities.str_to_big_int(x_1).multiply(blinding);

        this.x_2 = x_2;
        x_2_as_big_int = Utilities.str_to_big_int(x_2).multiply(blinding);

        this.alpha_one = alpha_one.multiply(blinding);

        this.generate_public_keys();

        id++;
    }

    /**
     * Method that generates and stores the credential's blinded and unblinded
     * public keys.
     */
    private void generate_public_keys() {
        BigInteger g_1 = system_parameters.get_g_1();
        BigInteger g_2 = system_parameters.get_g_2();
        BigInteger h_0 = system_parameters.get_h_0();
        BigInteger p = system_parameters.get_p();

        BigInteger g_one_pow_x_1 = g_1.modPow(x_1_as_big_int, p);
        BigInteger g_two_pow_x_2 = g_2.modPow(x_2_as_big_int, p);
        BigInteger h_0_pow_alpha = h_0.modPow(alpha_one, p);
        BigInteger base = g_one_pow_x_1.multiply(g_two_pow_x_2).mod(p);

        this.unblinded_public_key = base.multiply(h_0).mod(p);

        this.blinded_public_key = unblinded_public_key.modPow(alpha_one, p);

        this.show_protocol_brands_public_key = g_one_pow_x_1.multiply(g_two_pow_x_2).multiply(h_0_pow_alpha).mod(p);

        // important!!, public key cannot be equal to 1
        assert unblinded_public_key.compareTo(BigInteger.ONE) != 0;
        assert blinded_public_key.compareTo(BigInteger.ONE) != 0;

    }

    public BigInteger get_blinded_public_key() {
        return this.blinded_public_key;
    }

    public BigInteger get_x1_big_int() {
        return x_1_as_big_int;
    }

    public BigInteger get_x2_big_int() {
        return x_2_as_big_int;
    }

    public BigInteger get_alpha_one() {
        return alpha_one;
    }

    public BigInteger get_unblinded_public_key() {
        return unblinded_public_key;
    }

    public BigInteger get_brands_show_protocol_public_key() {
        return show_protocol_brands_public_key;
    }

    /**
     * Sets this credential's digital signature according to Brand's Issue Protocol.
     * 
     * @param c_prime_zero first signature element
     * @param r_prime_zero second siganture element
     */
    public void setSignature(BigInteger c_prime_zero, BigInteger r_prime_zero) {
        this.c_prime_zero = c_prime_zero;
        this.r_prime_zero = r_prime_zero;
    }

    /**
     * Prints this digital credentail's signature
     */
    public void printSignature() {
        System.out.println("c'0: " + c_prime_zero);
        System.out.println("r'0: " + r_prime_zero);
    }

}
