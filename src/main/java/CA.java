import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class CA {

    private SystemParameters systemParams;
    private BigInteger w_zero; // random value used in issue protocol
    private BigInteger masterSecret;
    private X9ECParameters x9;
    private ArrayList<ECPoint> userPoints;

    private ECPoint ec_generator;
    private ArrayList<BigInteger> testing = new ArrayList<>();

    private final BigInteger q = new BigInteger("2060482539417004714807271807532720159194878157261");
    private final BigInteger p = new BigInteger("126722927330356485972716360228361378886490200326758635063580789329619470494803880557558327132084315144776849176169714865071209572450289026191060457204039240766393131753949708301757283139290367502337143697243329250098665250159099169322160644987891564405304100997024323402318553668671843846560769150430780325889");
    private final BigInteger g_0 = new BigInteger("77892431251886878118231985443373842394949753687066869134988804136021582778525930673668862598795510663833591351729154915902687105749976049404466724780891697681133157484106077172700399828563248948202504294761256952752894303164095385771858414065268087999377076432060776344348284748617607017689393017527892943747");
    // Private key values for issuing protocol
    private final BigInteger y_1 = BigInteger.valueOf(700);
    private final BigInteger y_2 = BigInteger.valueOf(800);
    private final BigInteger x_0 = BigInteger.valueOf(900);

    public CA() {
        // Create P-224 type Elliptic Curve along with master secret and Q value (temp)
        x9 = NISTNamedCurves.getByName("P-224");
        masterSecret = BigInteger.ONE;
        ec_generator = this.x9.getG();
        userPoints = new ArrayList<ECPoint>();


        System.out.println("Prime q :" + q);
        System.out.println("Prime p: " + p);
        // sanity check
        assert q.bitLength() == 161;
        assert p.bitLength() == 1024;

        System.out.println("Generator g_0 :" + g_0);

        System.out.println("y_1 :" + y_1);
        assert y_1.compareTo(q) < 0 : "y_1 must be less than q";

        System.out.println("y_2 :" + y_2);
        assert y_2.compareTo(q) < 0 : "y_1 must be less than q";

        System.out.println("x_0 :" + x_0);
        assert x_0.compareTo(q) < 0 : "x_o must be less than q";

    }

    public SystemParameters get_system_parameters() {

        BigInteger g_1 = g_0.modPow(y_1, p);
        System.out.println("g_1 : " + g_1);

        //upgrade, g_2
        BigInteger g_2 = g_0.modPow(y_2, p);
        System.out.println("g_2 : " + g_2);

        BigInteger h_0 = g_0.modPow(x_0, p);
        System.out.println("h_0: " + h_0);

        this.systemParams = new SystemParameters(g_0, g_1, g_2, h_0, q, p);

        return this.systemParams;
    }

    // Set user point via point passed
    public void set_user_point(ECPoint userPoint) {
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
        ECPoint toCompare = ec_generator.multiply(input);

        return this.userPoints.contains(toCompare);
    }

    // Public function used to generate a point on the EC for a given identity
    public ECPoint generate_user_point(String identity){

        // Convert identity to hexadecimal hash and use as BigInteger to generate point
        // on curve, call method to set point in array of points
        BigInteger input = Utilities.str_to_big_int(identity);;
        ECPoint point = this.ec_generator.multiply(input);
        set_user_point(point);
        return point;
    }

    public BigInteger generate_a_zero() {
        // alongside generating this method, the CA pics also
        // picks a random value for w_zero
        w_zero = BigInteger.valueOf(99);
        System.out.println("w_zero:" + w_zero);
        assert w_zero.compareTo(q) < 0 : "Value must be less than q";

        BigInteger a_zero = systemParams.get_g_0().modPow(w_zero, p);
        System.out.println("a_zero:" + a_zero);
        assert a_zero.compareTo(p) < 0 : "Value must be less than q";

        return a_zero;
    }

    public BigInteger generate_r_zero(BigInteger c_zero, BigInteger x_1_as_int, BigInteger x_2_as_int) {

        BigInteger nominator = w_zero.subtract(c_zero).mod(q);
        System.out.println("Nominator in r_zero: " + nominator);
        assert nominator.compareTo(q) < 0 : "Must be less than q";

        BigInteger x_1_y_1 = x_1_as_int.multiply(y_1).mod(q);
        BigInteger x_2_y_2 = x_2_as_int.multiply(y_2).mod(q);

        BigInteger denominator = x_0.add(x_1_y_1).add(x_2_y_2).modInverse(q);
        System.out.println("Denominator in r_zero: " + denominator);
        assert denominator.compareTo(q) < 0 : "Must be less than q";

        // can also express a division as a multiplication
        return nominator.multiply(denominator).mod(q);
    }
}
