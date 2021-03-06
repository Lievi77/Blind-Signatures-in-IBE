import cryptid.ellipticcurve.TypeOneEllipticCurve;

import java.math.BigInteger;

public class SystemParameters {

    private final BigInteger g_0;
    private final BigInteger g_1;
    private final BigInteger g_2;
    private final BigInteger h_0;
    private final BigInteger q;
    private final BigInteger p;
    private final TypeOneEllipticCurve ec;
    private final BigInteger q_e;

    public SystemParameters(BigInteger g_0, BigInteger g_1, BigInteger g_2, BigInteger h_0, BigInteger q, BigInteger p, TypeOneEllipticCurve ec, BigInteger q_e){
        this.g_0 = g_0;
        this.p = p;
        this.g_1 = g_1;
        this.g_2 = g_2;
        this.h_0 = h_0;
        this.q = q;
        this.ec = ec;
        this.q_e = q_e;
    }

    //getters
    public BigInteger get_g_0(){
        return g_0;
    }

    //getters
    public BigInteger get_g_1(){
        return g_1;
    }

    public BigInteger get_g_2(){return g_2;}

    //getters
    public BigInteger get_h_0(){
        return h_0;
    }

    public BigInteger get_q(){ return q; }

    public BigInteger get_p(){return p;}

    public TypeOneEllipticCurve get_ec(){
        return  ec;
    }

    public BigInteger get_q_e(){
        return q_e;
    }
}
