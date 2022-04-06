import cryptid.ellipticcurve.TypeOneEllipticCurve;
import cryptid.ellipticcurve.point.affine.AffinePoint;
import cryptid.ellipticcurve.point.affine.generator.AffinePointGenerationStrategy;
import cryptid.ellipticcurve.point.affine.generator.GenerationStrategyFactory;
import cryptid.ellipticcurve.point.affine.generator.Mod3GenerationStrategy;
import cryptid.ibe.domain.PublicParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;

public class CA {

    private SystemParameters systemParams;
    private BigInteger w_zero; // random value used in issue protocol
    private ArrayList<AffinePoint> userPoints;

    private  AffinePoint ec_point_generator;

    private TypeOneEllipticCurve ca_ec;

    private ArrayList<BigInteger> testing = new ArrayList<>();

    private final BigInteger q = new BigInteger("2422930881716140125087463851781749592720970615567"); // q is 161 bits
    private final BigInteger p = new BigInteger("149014072275063050617006962132687356898245656476538731672582737560477369669186627767727693592006813496392501220719555187269800490769036527766250049683564456154163727432206843710408310939307764474876684253939216600211453850652175504958556351749469610816314826928730921635778585221191458892027053488849484251137"); //p is 1024 bits
    private final BigInteger g_0 = new BigInteger("91826688852231926746514962695724061705216991749939275957812079525533832690239186345974872529238111617223880177448991086091799805990347507313888863905424353224358276622305473810801445583072055323717148434522767724884753733070880381410090288307741836445271960608089443554705141690576656798921245983816603933600");

    // Private key values for issuing protocol
    //Can be anything as long as they're within Z_q
    private final BigInteger y_1 = BigInteger.valueOf(69420);
    private final BigInteger y_2 = BigInteger.valueOf(1137);
    private final BigInteger x_0 = BigInteger.valueOf(80085);

    public CA(PublicParameters publicParameters) {

        //assert q.mod(BigInteger.valueOf(12)).equals(BigInteger.valueOf(11));

        this.ca_ec = TypeOneEllipticCurve.ofOrder(q);

        final GenerationStrategyFactory<Mod3GenerationStrategy> generationStrategyFactory =
                ellipticCurve -> new Mod3GenerationStrategy(ellipticCurve, Utilities.secureRandom);

        AffinePointGenerationStrategy gen_strategy = generationStrategyFactory.newInstance(ca_ec);

        ec_point_generator = gen_strategy.generate(100).get();

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

        this.systemParams = new SystemParameters(g_0, g_1, g_2, h_0, q, p, this.ca_ec);

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
}
