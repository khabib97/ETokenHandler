using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using System.Collections;
using Org.BouncyCastle.Math;
using System;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Org.BouncyCastle.Crypto.Parameters;

namespace ETokenHandler
{
    internal class KeyPairHandler
    {
        public static X509Name GenerateRelativeDistinguishedName(Data enrollmentData)
        {

            IDictionary attributes = new Hashtable();
            IList ordering;

            attributes.Add(X509Name.CN, enrollmentData.getCommonName());
            attributes.Add(X509Name.O, enrollmentData.organization);
            attributes.Add(X509Name.OU, enrollmentData.organizationUnit);
            attributes.Add(X509Name.C, enrollmentData.country);
            attributes.Add(X509Name.ST, enrollmentData.state);
            attributes.Add(X509Name.L, enrollmentData.area);
            attributes.Add(X509Name.PostalCode, enrollmentData.postalCode);
            attributes.Add(X509Name.SerialNumber, enrollmentData.getSerialNumber());

            ordering = new ArrayList(attributes.Keys);
            return new X509Name(ordering, attributes);
        }

        public static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            SecureRandom secureRandom = new SecureRandom(new CryptoApiRandomGenerator());

            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(secureRandom, 2048);
            RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();

            rsaKeyPairGenerator.Init(keyGenerationParameters);

            return rsaKeyPairGenerator.GenerateKeyPair();
        }

        //CSR
        public static Pkcs10CertificationRequest GenerateCertificateSigningRequest(AsymmetricCipherKeyPair asymmetricCipherKeyPair,Data enrollmentData)
        {

            X509Name x509NameAsSubject = KeyPairHandler.GenerateRelativeDistinguishedName(enrollmentData);

            Asn1SignatureFactory asn1SignatureFactory = new Asn1SignatureFactory("SHA256WithRSA", asymmetricCipherKeyPair.Private);

            return new Pkcs10CertificationRequest(asn1SignatureFactory, x509NameAsSubject, asymmetricCipherKeyPair.Public, null, asymmetricCipherKeyPair.Private);
        }

        

        internal static void ImportPrivateKeyToSmartCard(AsymmetricCipherKeyPair asymmetricCipherKeyPair, Data enrollmentData)
        {
            String userPin = Console.ReadLine();

            Pkcs11 pkcs11 = new Pkcs11(Constants.PKCS11_LIBRARY_PATH, AppType.SingleThreaded);

            List<Slot> slots = pkcs11.GetSlotList(SlotsType.WithTokenPresent);
            Slot matchingSlot = slots[0];
            Session session = matchingSlot.OpenSession(SessionType.ReadWrite);

            session.Login(CKU.CKU_USER, userPin);

            WritingPrivateKeyToSmartCard(session, asymmetricCipherKeyPair, enrollmentData.ID);

            session.Logout();

        }

        //Write Private Key to Smard Card
        internal static void WritingPrivateKeyToSmartCard(Session session, AsymmetricCipherKeyPair asymmetricCipherKeyPair, BigInteger enrollmentID)
        {
            RsaPrivateCrtKeyParameters rsaPrivKey = (RsaPrivateCrtKeyParameters)asymmetricCipherKeyPair.Private;

            byte[] ckaId = enrollmentID.ToByteArrayUnsigned();

            List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
            //Common attribute
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, "Your_Label"));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_SUBJECT, enrollmentID.ToString()));

            //Must add this attribute to create objcet
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_MODULUS, rsaPrivKey.Modulus.ToByteArrayUnsigned()));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE_EXPONENT, rsaPrivKey.Exponent.ToByteArrayUnsigned()));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, rsaPrivKey.PublicExponent.ToByteArrayUnsigned()));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIME_1, rsaPrivKey.P.ToByteArrayUnsigned()));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIME_2, rsaPrivKey.Q.ToByteArrayUnsigned()));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_COEFFICIENT, rsaPrivKey.QInv.ToByteArrayUnsigned()));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_EXPONENT_1, rsaPrivKey.DP.ToByteArrayUnsigned()));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_EXPONENT_2, rsaPrivKey.DQ.ToByteArrayUnsigned()));

            //write object/private key to smart card
            session.CreateObject(objectAttributes);
        }

    }
}