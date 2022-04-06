import cryptid.ellipticcurve.point.affine.AffinePoint;
import cryptid.ibe.domain.PublicParameters;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;

public class CA {

    private SystemParameters systemParams;
    private BigInteger w_zero; // random value used in issue protocol
    private ArrayList<AffinePoint> userPoints;

    private  AffinePoint ec_generator;

    private PublicParameters publicParameters;

    private ArrayList<BigInteger> testing = new ArrayList<>();

    private final BigInteger q = new BigInteger("2060482539417004714807271807532720159194878157261"); // q is 161 bits
    private final BigInteger p = new BigInteger("126722927330356485972716360228361378886490200326758635063580789329619470494803880557558327132084315144776849176169714865071209572450289026191060457204039240766393131753949708301757283139290367502337143697243329250098665250159099169322160644987891564405304100997024323402318553668671843846560769150430780325889"); //p is 1024 bits
    private final BigInteger g_0 = new BigInteger("77892431251886878118231985443373842394949753687066869134988804136021582778525930673668862598795510663833591351729154915902687105749976049404466724780891697681133157484106077172700399828563248948202504294761256952752894303164095385771858414065268087999377076432060776344348284748617607017689393017527892943747");

    // Private key values for issuing protocol
    //Can be anything as long as they're within Z_q
    private final BigInteger y_1 = BigInteger.valueOf(69420);
    private final BigInteger y_2 = BigInteger.valueOf(1137);
    private final BigInteger x_0 = BigInteger.valueOf(80085);

    public CA(PublicParameters publicParameters) {

        //assert q.mod(BigInteger.valueOf(12)).equals(BigInteger.valueOf(11));

        this.publicParameters = publicParameters;

        ec_generator = publicParameters.getPointP();
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

        this.systemParams = new SystemParameters(g_0, g_1, g_2, h_0, q, p, publicParameters.getEllipticCurve());

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
        AffinePoint toCompare = ec_generator.multiply(input, this.publicParameters.getEllipticCurve());

        return this.userPoints.contains(toCompare);
    }

    // Public function used to generate a point on the EC for a given identity
    public AffinePoint generate_user_point(String identity){

        // Convert identity to hexadecimal hash and use as BigInteger to generate point
        // on curve, call method to set point in array of points
        BigInteger input = Utilities.str_to_big_int(identity);
        //ECPoint point = this.ec_generator.multiply(input);
        AffinePoint user_point = publicParameters.getPointP().multiply(input, publicParameters.getEllipticCurve());
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
