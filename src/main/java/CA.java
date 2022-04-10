import cryptid.ellipticcurve.TypeOneEllipticCurve;
import cryptid.ellipticcurve.point.affine.AffinePoint;
import cryptid.ellipticcurve.point.affine.generator.AffinePointGenerationStrategy;
import cryptid.ellipticcurve.point.affine.generator.GenerationStrategyFactory;
import cryptid.ellipticcurve.point.affine.generator.Mod3GenerationStrategy;
import cryptid.ibe.domain.PublicParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

public class CA {
    private static BigInteger ZERO = BigInteger.ZERO;
    private static BigInteger ONE = BigInteger.ONE;
    private static BigInteger ELEVEN = BigInteger.valueOf(11);
    private static BigInteger TWELVE = BigInteger.valueOf(12);


    private SystemParameters systemParams;
    private BigInteger w_zero; // random value used in issue protocol
    private ArrayList<AffinePoint> userPoints;

    private  AffinePoint ec_point_generator;

    private TypeOneEllipticCurve ca_ec;

    private PublicParameters publicParameters;

    private ArrayList<BigInteger> testing = new ArrayList<>();

    private final  BigInteger q ; // q is 161 bits
    private  BigInteger p =  new BigInteger("95557508834940487002394549912474855075355941045472278079660199271890299480793004986167492457243943734902856056978139695086552588487486139739769073540406400917959400992497559114522567280027559762801058013795235777390256233552632575585875110396339402707124675781761358508825403322692246163322662332555116820669"); //p is 1024 bits
    private final BigInteger g_0= new BigInteger("11855948683433545137405101925416292715741570131669899054441121451722714917935993874283489846598167019859199246833760812349097349102285004956527401758920455582430977859718822338454972043117524702561490636553240756715048518092567685541036796242614795453377543614596049227899751218480952414791463059802954416479");

    // Private key values for issuing protocol
    //Can be anything as long as they're within Z_q
    private final BigInteger y_1 = BigInteger.valueOf(69420);
    private final BigInteger y_2 = BigInteger.valueOf(1137);
    private final BigInteger x_0 = BigInteger.valueOf(80085);



    public CA(PublicParameters publicParameters) {
        //set up p,q,g_0
        q = publicParameters.getEllipticCurve().getFieldOrder();

        this.ca_ec = publicParameters.getEllipticCurve();

        this.publicParameters = publicParameters;

        //ec_point_generator = gen_strategy.generate(100).get();
        ec_point_generator = publicParameters.getPointP();

        userPoints = new ArrayList<>();
        /*
         * Assertions to ensure pk and pb y_i's and x_0 are within Zq
         */
        //System.out.println("y_1 :" + y_1);
        assert y_1.compareTo(q) < 0 : "y_1 must be less than q";

        //System.out.println("y_2 :" + y_2);
        assert y_2.compareTo(q) < 0 : "y_1 must be less than q";

        //System.out.println("x_0 :" + x_0);
        assert x_0.compareTo(q) < 0 : "x_o must be less than q";
    }

    public SystemParameters get_system_parameters() {

        BigInteger g_1 = g_0.modPow(y_1, p);
        //System.out.println("g_1 : " + g_1);

        //upgrade, g_2
        BigInteger g_2 = g_0.modPow(y_2, p);
        //System.out.println("g_2 : " + g_2);

        BigInteger h_0 = g_0.modPow(x_0, p);
        //System.out.println("h_0: " + h_0);

        this.systemParams = new SystemParameters(g_0, g_1, g_2, h_0, q, p, publicParameters.getEllipticCurve(), publicParameters.getQ() );

        return this.systemParams;
    }

    // Set user point via point passed
    public void set_user_point(AffinePoint userPoint) {
        userPoints.add(userPoint);
    }

    // Primary verify function used to check if a point already exists
    // Need to add one that checks based off of X and Y coordinates though
    public boolean verify_user_point(ECPoint userPoint) {
        return this.userPoints.contains(userPoint);
    }

    // Secondary verify function used for if point is not available
    public boolean verify_user_point(String identity) {
        BigInteger input = Utilities.str_to_big_int(identity);
        AffinePoint toCompare = ec_point_generator.multiply(input, ca_ec);

        return this.userPoints.contains(toCompare);
    }

    // Public function used to generate a point on the EC for a given identity
    public AffinePoint generate_user_point(String identity){

        // Convert identity to hexadecimal hash and use as BigInteger to generate point
        // on curve, call method to set point in array of points
        BigInteger input = Utilities.str_to_big_int(identity);
        //ECPoint point = this.ec_generator.multiply(input);
        AffinePoint user_point = ec_point_generator.multiply(input, ca_ec);
        set_user_point(user_point);
        return user_point;
    }

    public BigInteger generate_a_zero() {
        // alongside generating this method, the CA pics also
        // picks a random value for w_zero
        w_zero = new BigInteger(q.bitLength()-1, Utilities.secureRandom);
        //System.out.println("w_zero:" + w_zero);
        assert w_zero.compareTo(q) < 0 : "Value must be less than q";

        BigInteger a_zero = systemParams.get_g_0().modPow(w_zero, p);
        //System.out.println("a_zero:" + a_zero);
        assert a_zero.compareTo(p) < 0 : "Value must be less than q";

        return a_zero;
    }

    public BigInteger generate_r_zero(BigInteger c_zero, BigInteger x_1_as_int, BigInteger x_2_as_int) {

        BigInteger nominator = w_zero.subtract(c_zero).mod(q);
        //System.out.println("Nominator in r_zero: " + nominator);
        assert nominator.compareTo(q) < 0 : "Must be less than q";

        BigInteger x_1_y_1 = x_1_as_int.multiply(y_1).mod(q);
        BigInteger x_2_y_2 = x_2_as_int.multiply(y_2).mod(q);

        BigInteger denominator = x_0.add(x_1_y_1).add(x_2_y_2).modInverse(q);
        //System.out.println("Denominator in r_zero: " + denominator);
        assert denominator.compareTo(q) < 0 : "Must be less than q";

        // can also express a division as a multiplication
        return nominator.multiply(denominator).mod(q);
    }

    public TypeOneEllipticCurve get_ec(){
        return this.ca_ec;
    }

    public BigInteger get_generator() {

        BigInteger r;

        do {
            r  = new BigInteger( 1024 - q.bitLength(), Utilities.secureRandom);
            p = q.multiply(r); // get 1024 bit p (1024 - number_of_bits)
            p = p.add(BigInteger.ONE);
        } while (!p.isProbablePrime(100) || p.bitLength() < 1024);

        assert q.isProbablePrime(100) : "must be a prime";
        assert q.mod(TWELVE).equals(ELEVEN) : "Must be congruent 11 modulo 12";
        assert p.isProbablePrime(100) : "must be prime";
        assert p.subtract(ONE).mod(q).equals(ZERO): "p-1 must be divisible by q"; // ensures p-1 is divisible by p
        assert p.bitLength() == 1024;

        BigInteger h = new BigInteger(160, new SecureRandom());

        assert h.compareTo(BigInteger.ONE) > 0 : "H has to be greater than 1";

        BigInteger exp = p.subtract(BigInteger.ONE).divide(q);

        BigInteger g = h.modPow(exp, p);

        assert g.compareTo(BigInteger.ONE) > 0 : "G CANNOT BE ONE";

        return g;
    }
}
