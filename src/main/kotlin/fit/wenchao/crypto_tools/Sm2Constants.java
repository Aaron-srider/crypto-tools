package fit.wenchao.crypto_tools;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;

import java.math.BigInteger;


/**
 * @author ccm
 */
public interface Sm2Constants {

    /**
     * 以下为SM2推荐曲线参数
     */
    SM2P256V1Curve CURVE = new SM2P256V1Curve();
    BigInteger SM2_ECC_P = CURVE.getQ();
    BigInteger SM2_ECC_A = CURVE.getA().toBigInteger();
    BigInteger SM2_ECC_B = CURVE.getB().toBigInteger();
    BigInteger SM2_ECC_N = CURVE.getOrder();
    BigInteger SM2_ECC_H = CURVE.getCofactor();
    BigInteger SM2_ECC_GX = new BigInteger(
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
    BigInteger SM2_ECC_GY = new BigInteger(
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);
    ECPoint G_POINT = CURVE.createPoint(SM2_ECC_GX, SM2_ECC_GY);
    ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(CURVE, G_POINT,
            SM2_ECC_N, SM2_ECC_H);
    byte[] USER_ID = "1234567812345678".getBytes();

}
