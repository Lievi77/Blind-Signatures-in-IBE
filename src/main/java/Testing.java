import java.math.BigInteger;
import java.security.SecureRandom;

public class Testing {

    // Class used for testing
    public static void main(String[] args) {

        Testing test = new Testing();
        // test.test_two_attributes();
        test.testIssueProtocol();
        // BigInteger G = get_generator(161);
        // System.out.println("Generator g_0: " +G);
        test.testShowProtocol();

    }

    private void testShowProtocol() {
        Client alice = new Client("alice@test.com");
        CA ca = new CA();

        SystemParameters sys_param = ca.get_system_parameters();

        alice.setSystemParameters(sys_param);

        // Now Alice requests a digital credential
        alice.requestCredential(ca);

        /*
         * after this method is executed, alice now has a valid
         * digital credential issued by the CA.
         * Can be accessed via alice.credential
         */
        // now, use showProtocol
        alice.show();

    }

    private void test_two_attributes() {
        CA ca = new CA();
        SystemParameters params = ca.get_system_parameters();

        // simulating alpha 1
        BigInteger alpha_one = BigInteger.valueOf(100);

        System.out.println("~~Testing Credential 2 attr");
        Credential credential = new Credential(params,
                "p1", "p2", alpha_one);
    }

    private void testIssueProtocol() {
        Client alice = new Client("alice@test.com");
        CA ca = new CA();

        SystemParameters sys_param = ca.get_system_parameters();

        alice.setSystemParameters(sys_param);

        // Now Alice requests a digital credential
        alice.requestCredential(ca);

        /*
         * after this method is executed, alice now has a valid
         * digital credential issued by the CA.
         * Can be accessed via alice.credential
         */
    }

    private static BigInteger get_generator(int number_of_bits) {
        BigInteger q;
        BigInteger p;

        do {
            q = BigInteger.probablePrime(number_of_bits, new SecureRandom()); //

            p = q.multiply(BigInteger.TWO.pow(1024 - number_of_bits)); // get 1024 bit p (1024 - number_of_bits)

            p = p.add(BigInteger.ONE);
            // System.out.println("Is p Prime? " + p.isProbablePrime(10));

        } while (!p.isProbablePrime(10));

        System.out.println(q.bitLength() + " Prime q: " + q);
        System.out.println(p.bitLength() + " Prime p: " + p);

        assert q.isProbablePrime(100) : "must be a prime";
        assert p.isProbablePrime(100) : "must be prime";
        assert p.subtract(BigInteger.ONE).mod(q).equals(BigInteger.ZERO); // ensures p-1 is divisible by q
        assert p.bitLength() == 1024;

        BigInteger h = new BigInteger(160, new SecureRandom());

        assert h.compareTo(BigInteger.ONE) > 0 : "H has to be greater than 1";

        BigInteger exp = p.subtract(BigInteger.ONE).divide(q);

        BigInteger g = h.modPow(exp, p);

        assert g.compareTo(BigInteger.ONE) > 0 : "G CANNOT BE ONE";

        return g;
    }

}
