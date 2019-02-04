using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;

namespace ETokenHandler
{
    class Program
    {

        static void Main(string[] args)
        {
            KeyPairHandler keyPairHandler = new KeyPairHandler();
            Data enrollmentData = new Data();

            //initialize safeNet .dll . 
            //put your .dll file inside x64 or x32 folder.
            //keep these folders in *.exe's folder
            if (Environment.Is64BitProcess)
                Constants.PKCS11_LIBRARY_PATH = @"x64\eTPKCS11.dll";
            else
                Constants.PKCS11_LIBRARY_PATH = @"x32\eTPKCS11.dll";

            //need to implement
            PopulateEnrollmentData(out enrollmentData);

            String generationMode = Console.ReadLine();
            switch (generationMode)
            {
                case "certificate":
                    X509Certificate x509Certificate = CertificateHandler.CertificateGenerator(enrollmentData.ID);
                    //write certificate to smart card
                    CertificateHandler.ImportCertificateToSmartCard(x509Certificate);
                    break;
                case "key":
                    // RSA 2048
                    AsymmetricCipherKeyPair asymmetricCipherKeyPair = KeyPairHandler.GenerateKeyPair();
                    // CSR 
                    Pkcs10CertificationRequest csr = KeyPairHandler.GenerateCertificateSigningRequest(asymmetricCipherKeyPair,enrollmentData);
                    //need to implement
                    GenerationRequestToServerForDotP7B();
                    //private key write to smart card(safeNet e-Token)
                    KeyPairHandler.ImportPrivateKeyToSmartCard(asymmetricCipherKeyPair, enrollmentData);
                    break;
            }

            Console.ReadKey();
        }

        private static void GenerationRequestToServerForDotP7B()
        {
            //As per your need
            throw new NotImplementedException();
        }

        private static void PopulateEnrollmentData(out Data enrollmentData)
        {
            //put your data polulation logic here
            throw new NotImplementedException();
        }
    }
}
