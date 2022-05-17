import cryptid.ellipticcurve.TypeOneEllipticCurve;
import cryptid.ellipticcurve.point.affine.AffinePoint;
import cryptid.ibe.IdentityBasedEncryption;
import cryptid.ibe.domain.CipherTextTuple;
import cryptid.ibe.domain.PrivateKey;
import java.math.BigInteger;

public class Client {
    private final String email;
    private Credential credential;
    private SystemParameters systemParameters;
    private AffinePoint user_ec_point;
    private AffinePoint user_ec_point_prime;
    private BigInteger r; // integer used to blind the EC point
    private BigInteger r_inv;
    private BigInteger r_x; // used to blind and unblind C_x
    private BigInteger r_y; // used to blind and unblind C_y
    private BigInteger alpha; //blinding factor

    /**
     * Construct a new client with an email.
     *
     * */
    public Client(String email) {
        this.email = email;
    }

    public AffinePoint get_user_point(){
        return user_ec_point;
    }

    public AffinePoint get_user_blinded_point(){
        return user_ec_point_prime;
    }

    public String get_x(){
        return user_ec_point.getX().toString();
    }

    public String get_y(){
        return user_ec_point.getY().toString();
    }

    public String get_blinded_x(){
        return user_ec_point_prime.getX().toString();
    }

    public String get_blinded_y(){
        return user_ec_point_prime.getY().toString();
    }

    public String getEmail() {
        return email;
    }

    public void setSystemParameters(SystemParameters params) {
        this.systemParameters = params;
    }

    // getter
    private Credential getCredential() {
        return credential;
    }

    /**
     *  Request a Brand's digital credential from a particular CA.
     *
     * @param admin the CA receiving the request.
     */
    public void requestCredential(CA admin) {

        this.systemParameters = admin.get_system_parameters();

        BigInteger q = systemParameters.get_q();

        BigInteger a_zero = admin.generate_a_zero();

        BigInteger alpha_one, alpha_two, alpha_three;

        alpha_one = new BigInteger(q.bitLength()-1, Utilities.secureRandom); // blinding factor
        this.alpha= alpha_one;

        assert alpha_one.compareTo(q) < 0 : "Value needs to be less than q";
        assert alpha_one.gcd(q).equals(BigInteger.ONE);

        alpha_two = new BigInteger(q.bitLength()-1, Utilities.secureRandom);

        assert alpha_two.compareTo(q) < 0 : "Value needs to be less than q";

        alpha_three = new BigInteger(q.bitLength()-1, Utilities.secureRandom);;
        //System.out.println("Alpha_three: " + alpha_three);
        assert alpha_three.compareTo(q) < 0 : "Value needs to be less than q";

        // create credential
        // here in the credential, we put as x_1, x_2 the coordinates
        // of the EC
        System.out.println("-->Requesting EC point for " + email);
        AffinePoint assigned_point = admin.generate_user_point(email);

        String EC_x = assigned_point.getX().toString();
        String EC_y = assigned_point.getY().toString();

        System.out.println("-->Assigned EC point :(" +EC_x +", " + EC_y+")" );

        this.user_ec_point = assigned_point;

        // r has to be in Z_{q_e}
        r = new BigInteger(systemParameters.get_q_e().bitLength()-1, Utilities.secureRandom); //for now r is fixed for testing
        r_inv = r.modInverse(systemParameters.get_q_e());
        TypeOneEllipticCurve EC = systemParameters.get_ec();

        user_ec_point_prime = user_ec_point.multiply(r, EC);

       assert user_ec_point_prime.multiply(r_inv,EC).equals(user_ec_point) : "Inversing must be true";

        credential = new Credential(systemParameters, EC_x, EC_y, alpha_one);
        // to get h,as in the protocol , call credential.get_blinded_public_key

        BigInteger c_prime_zero = this.generate_c_prime_zero(alpha_two, alpha_three, a_zero);

        assert c_prime_zero.compareTo(q) < 0 : "Value needs to be less than q";

        BigInteger c_zero = c_prime_zero.subtract(alpha_two).mod(q);

        assert c_zero.compareTo(q) < 0 : "Value needs to be less than q";

        // now, send c_zero to CA
        BigInteger r_zero = admin.generate_r_zero(c_zero, credential.get_x1_big_int(), credential.get_x2_big_int());

        boolean isValid = this.verify_signature(a_zero, r_zero, c_zero);

        if (isValid) {
            // create r'_zero
            System.out.println("Check passed, issuing signature");

            BigInteger numerator = r_zero.add(alpha_three).mod(q);
            BigInteger denominator = alpha_one.modInverse(q);
            BigInteger r_prime_zero = numerator.multiply(denominator).mod(q);
            this.credential.setSignature(c_prime_zero, r_prime_zero);
            credential.printSignature();

        } else {
            System.out.println("Error!!!");
        }

    }

    private boolean verify_signature(BigInteger a_zero, BigInteger r_zero, BigInteger c_zero) {
        BigInteger g_0 = systemParameters.get_g_0();
        BigInteger p = systemParameters.get_p();

        BigInteger g_zero_pow_c_zero = g_0.modPow(c_zero, p);

        BigInteger pow_r_zero = credential.get_unblinded_public_key().modPow(r_zero, p);

        BigInteger may_be_a_zero = g_zero_pow_c_zero.multiply(pow_r_zero).mod(p);

        assert a_zero.equals(may_be_a_zero);

        return a_zero.equals(may_be_a_zero);
    }

    private BigInteger generate_c_prime_zero(BigInteger alpha_two, BigInteger alpha_three, BigInteger a_zero) {

        BigInteger q = systemParameters.get_q();
        BigInteger h = this.credential.get_blinded_public_key();
        BigInteger g_0 = systemParameters.get_g_0();
        BigInteger p = systemParameters.get_p();

        BigInteger g_zero_pow_alpha_two = g_0.modPow(alpha_two, p);
        BigInteger middle_part = credential.get_unblinded_public_key().modPow(alpha_three, p);
        BigInteger alongside = g_zero_pow_alpha_two.multiply(middle_part).multiply(a_zero).mod(p);

        String text = h.toString() + alongside;

        String hex_hashed_big_int = Utilities.hash_attribute(text);

        BigInteger hex_hashed_as_big_int = new BigInteger(hex_hashed_big_int, 16);

        assert hex_hashed_as_big_int.compareTo(q) < 0 : "Must be less than q";
        assert hex_hashed_as_big_int.compareTo(BigInteger.ZERO) > 0 : "Must be within Z_Q";

        return hex_hashed_as_big_int;
    }

    // Show protocol
    // i.e, proof of knowledge
    public void showBlindedCredentialsToPKG(PKGWrapper pkgWrapper, Credential credential_to_show) {

        // get everything from system parameters
        BigInteger q = this.systemParameters.get_q();
        BigInteger p = this.systemParameters.get_p();
        BigInteger g_1 = this.systemParameters.get_g_1();
        BigInteger g_2 = this.systemParameters.get_g_2();
        BigInteger h_0 = this.systemParameters.get_h_0();

        // get attributes from credential
        BigInteger x_1 = credential_to_show.get_x1_big_int();
        BigInteger x_2 = credential_to_show.get_x2_big_int();
        BigInteger alpha = credential_to_show.get_alpha_one();

        // generate a
        // we only have 2 generators, thus we spawn 3 w's
        // one for each g_i and one for h_0
        BigInteger w_1 = BigInteger.valueOf(29305);
        BigInteger w_2 = BigInteger.valueOf(41999);
        BigInteger w_3 = BigInteger.valueOf(1089920);
        assert w_1.compareTo(q) < 0 : "Must be Less than q";
        assert w_2.compareTo(q) < 0 : "Must be Less than q";
        assert w_3.compareTo(q) < 0 : "Must be Less than q";

        BigInteger g_1_pow_w_1 = g_1.modPow(w_1, p); // mod p!
        BigInteger g_2_pow_w_2 = g_2.modPow(w_2, p);
        BigInteger h_0_pow_w_3 = h_0.modPow(w_3, p);

        BigInteger a = g_1_pow_w_1.multiply(g_2_pow_w_2).multiply(h_0_pow_w_3).mod(p);

        BigInteger c = pkgWrapper.get_show_protocol_c();

        // create r's
        BigInteger r_1 = c.multiply(x_1).add(w_1).mod(q);
        BigInteger r_2 = c.multiply(x_2).add(w_2).mod(q);
        BigInteger r_3 = c.multiply(alpha).add(w_3).mod(q);

        pkgWrapper.verify_credential_signature(credential_to_show, a, r_1, r_2, r_3);
    }

    /**
     * Encrypt using receiver_public_key and ibe scheme a message.
     *
     * @param receiver_public_key the receiver's public key as an elliptic curve point.
     * @param ibe the ibe scheme to use.
     * @param message the message to encrypt.
     */
    public CipherTextTuple sendMessage(AffinePoint receiver_public_key, IdentityBasedEncryption ibe, String message){
        return ibe.encrypt(message,receiver_public_key);
    }

    //must be run after requestCredential
    public Credential blindCredentialX(){
        // random r_x in Z_q
        BigInteger q = systemParameters.get_q();
        
        BigInteger x = user_ec_point.getX();
        assert x.compareTo(q) < 0 : "x must be in Z_q";
        BigInteger x_prime = user_ec_point_prime.getX();
        
        //mult inverse of x
        BigInteger x_inv = x.modInverse(q);

        r_x = x_prime.multiply(x_inv).mod(q); //may cause a bug
        assert (r_x.multiply(x).mod(q)).equals(x_prime) : "must be equal";

        //C_x = C^(r_x) = g1^x' . g2^(r_x)y . h0^(r_x)alpha

        BigInteger g_1 = systemParameters.get_g_1();
        BigInteger g_2 = systemParameters.get_g_2();
        BigInteger h_0 = systemParameters.get_h_0();
        BigInteger p = systemParameters.get_p();
        BigInteger y = user_ec_point.getY();

        BigInteger g_1_pow_x_prime = g_1.modPow(x_prime,p);
        BigInteger g_2_pow_r_x_y = g_2.modPow(r_x.multiply(y), p );
        BigInteger h_0_pow_r_x_alpha = h_0.modPow(r_x.multiply(alpha),p);

            BigInteger blinded_cx = g_1_pow_x_prime.multiply(g_2_pow_r_x_y).multiply(h_0_pow_r_x_alpha).mod(q);

        return new Credential(systemParameters,x_prime.toString(),y.toString(), alpha, r_x);
    }

    //must be run after requestCredential
    public Credential blindCredentialY(){
        // random r_x in Z_q
        BigInteger q = systemParameters.get_q();
        BigInteger p = systemParameters.get_p();

        BigInteger x = user_ec_point.getX();
        BigInteger y = user_ec_point.getY();
        BigInteger y_prime = user_ec_point_prime.getY();

        //mult inverse of x
        BigInteger y_inv = y.modInverse(q);

        r_y = y_prime.multiply(y_inv).mod(q); //may cause a bug
        assert r_y.multiply(y).mod(q).equals(y_prime) : "must be equal";
        assert r_y.modInverse(q).multiply(y_prime).mod(q).equals(y): "equal";

        BigInteger g_1 = systemParameters.get_g_1();
        BigInteger g_2 = systemParameters.get_g_2();
        BigInteger h_0 = systemParameters.get_h_0();
        //C_y = C^(r_y) = g1^(r_y)x . g2^y' . h0^(r_y)alpha.
        BigInteger g1_pow_r_y_x = g_1.modPow(r_y.multiply(x),p);
        BigInteger g2_pow_y_prime = g_2.modPow(y_prime,p);
        BigInteger h0_pow_r_y = h_0.modPow(r_y.multiply(alpha),p);

        BigInteger blinded_cy = (g1_pow_r_y_x.multiply(g2_pow_y_prime).multiply(h0_pow_r_y)).mod(q);

        return new Credential(systemParameters,x.toString(),y_prime.toString(), alpha, r_y);
    }

    public PrivateKey unblind_private_key(PrivateKey pk){

        TypeOneEllipticCurve EC = systemParameters.get_ec();

        AffinePoint k_prime= pk.getData();

        AffinePoint k = k_prime.multiply(r_inv,EC);

        return new PrivateKey(k);
    }

}
