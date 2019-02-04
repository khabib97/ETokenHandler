using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections;
using System.Collections.Generic;

namespace ETokenHandler
{
    class CertificateHandler
    {
        internal static X509Certificate CertificateGenerator(BigInteger enrollmentID)
        {
            //.p7b to string
            String stringifyCertificate = GetCertificateByteArray(enrollmentID);
            X509Certificate x509certificate = GenerateCertificate(stringifyCertificate);

            return x509certificate;
        }

        internal static void ImportCertificateToSmartCard(X509Certificate certificate)
        {
            String userPin = Console.ReadLine();

            Pkcs11 pkcs11 = new Pkcs11(Constants.PKCS11_LIBRARY_PATH, AppType.SingleThreaded);

            List<Slot> slots = pkcs11.GetSlotList(SlotsType.WithTokenPresent);
            Slot matchingSlot = slots[0];
            Session session = matchingSlot.OpenSession(SessionType.ReadWrite);

            session.Login(CKU.CKU_USER, userPin);

            // Get public key from certificate
            AsymmetricKeyParameter pubKeyParams = certificate.GetPublicKey();

            if (!(pubKeyParams is RsaKeyParameters))
                throw new NotSupportedException("Currently only RSA keys are supported");

            RsaKeyParameters rsaPubKeyParams = (RsaKeyParameters)pubKeyParams;

            // Find corresponding private key
            List<ObjectAttribute> privKeySearchTemplate = new List<ObjectAttribute>();
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_MODULUS, rsaPubKeyParams.Modulus.ToByteArrayUnsigned()));
            privKeySearchTemplate.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, rsaPubKeyParams.Exponent.ToByteArrayUnsigned()));

            List<ObjectHandle> foundObjects = session.FindAllObjects(privKeySearchTemplate);
            if (foundObjects.Count != 1)
                throw new Exception("Corresponding RSA private key not found");
            else
                Console.WriteLine("Corresponding private key found");

            ObjectHandle privKeyObjectHandle = foundObjects[0];

            // Read CKA_LABEL and CKA_ID attributes of private key
            List<CKA> privKeyAttrsToRead = new List<CKA>();
            privKeyAttrsToRead.Add(CKA.CKA_LABEL);
            privKeyAttrsToRead.Add(CKA.CKA_ID);

            List<ObjectAttribute> privKeyAttributes = session.GetAttributeValue(privKeyObjectHandle, privKeyAttrsToRead);

            // Define attributes of new certificate object
            List<ObjectAttribute> certificateAttributes = new List<ObjectAttribute>();
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, true));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, privKeyAttributes[0].GetValueAsString()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_TRUSTED, false));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SUBJECT, certificate.SubjectDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ID, privKeyAttributes[1].GetValueAsByteArray()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_ISSUER, certificate.IssuerDN.GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_SERIAL_NUMBER, new DerInteger(certificate.SerialNumber).GetDerEncoded()));
            certificateAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, certificate.GetEncoded()));

            // Create certificate object
            session.CreateObject(certificateAttributes);

            session.Logout();
        }

        private static X509Certificate GenerateCertificate(String certificateString)
        {
            byte[] bytes = Convert.FromBase64CharArray(certificateString.ToCharArray(), 0, certificateString.Length);
            CmsSignedData cmsSignedData = new CmsSignedData(bytes);

            IX509Store store = cmsSignedData.GetCertificates("Collection");
            ICollection allCertificates = store.GetMatches(null);

            IEnumerator enumerator = allCertificates.GetEnumerator();
            while (enumerator.MoveNext())
            {
                X509Certificate x509 = (X509Certificate)enumerator.Current;
                Console.WriteLine("Server Generated Certificate: " + x509.ToString());
                return x509;
            }
            throw new Exception("Certificate generation error");
        }

        private static string GetCertificateByteArray(BigInteger enrollmentID)
        {
            //fetch generated .p7b from server and convert to string
            //Demo-like 
            //HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            //Stream stream = response.GetResponseStream();
            //StreamReader streamReader = new StreamReader(stream);
            //return netStream = streamReader.ReadToEnd();
            throw new NotImplementedException();
        }
    }
}
