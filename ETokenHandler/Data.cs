using Org.BouncyCastle.Math;
using System;
namespace ETokenHandler
{
    internal class Data
    {
        public BigInteger ID { get; set; }
        public String firstName { get; set; }
        public String lastName { get; set; }
        public String organization { get; set; }
        public String organizationUnit { get; set; }
        public String area { get; set; }
        public String country { get; set; }
        public String state { get; set; }
        public String postalCode { get; set; } 
        public String serialNumber { get; set; }
        public String passPhase { get; set; }
        public String identityType { get; set; }
        public String identityNo { get; set; }

        //need for digital signature purpose
        public String getCommonName()
        {
            return lastName.Trim() + " " + firstName.Trim();
        }

        public String getSerialNumber()
        {
            return identityType + "" + Utility.SHA1(identityNo);
        }
    }
}