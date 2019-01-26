# ssl-info
A minimal golang application to inspect SSL/TLS certificates exchanged with HTTPS servers

## Usage
```
Usage of ssl-info:
  -host string
    	the host to connect to
  -port string
    	the port to use (default "443")
```

## Example:
```
go run main.go -host=www.github.com
Version: 771
HandshakeComplete: true
PeerCertificates:
    Subject: SERIALNUMBER=5157550,CN=github.com,O=GitHub\, Inc.,L=San Francisco,ST=California,C=US
    NotBefore: 2018-05-08 00:00:00 +0000 UTC
    NotAfter: 2020-06-03 12:00:00 +0000 UTC
    PublicKey: 30820122300D06092A864886F70D01010105000382010F003082010A0282010100C63CAAF23C970C3AC14F28AD72707DD3CEB9B56073A4749B8A7746FD7A98424CC53019579AA9330BE15D4D1058CA7799C393F3F97590BCBFBBE095BA2EC58D736105D31084A8B389B82F738CF02A6EBEEEAE834B8211B161FD7761DA9B1B9A23FF8C7EA20106DDD17F539608C15AFAE7C0CAC8448C57A7A8615F660D57D3B896ACB64A9CC1EAE8FB964029F61530B504B0CC05B684C32459957FA26590E5B0B31A7559C43F31140AD5CCAA3A8505520632960761DF27820CF785DB6031F00950C5B71A23E1B07D02F5141EC9CBE87E2A3304F6513F529815E90B76475C4D4A6BC50815AEF8D157E9EA7014FFC945B90C7CBCF46DE60552F98C80BB7056910F4B0203010001
    Version: 3
    Issuer: CN=DigiCert SHA2 Extended Validation Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
    SerialNumber: 13324412563135569597699362973539517727
    PublicKeyAlgorithm: RSA
    SignatureAlgorithm: SHA256-RSA
    Signature: 700F5A96A758E5BF8A9DA827982B007F26A907DABA7B82544FAF69CFBCF259032BF2D5745825D81EA42076626029732AD7DCCC6F77856BCA6D24F83513473FD2E2690A9D342D7B7B9BCD1E75D5506C3ECB1CA330B1AA9207A93A767645BD7891C4CE1A9E22E40B89BAE68CC17982A3B8D4C0FC1F2DED4D5255412AA83A2CAD0772AE0AD2C667C44F07171899F765A95760155A344C11CFF6CF6B213680EFC6F15463263539EEBBC483649B240A73ECA0481673C8B9D7485556987AF7BB975C69A406180478DAFE9876BE222F7F0777874E88199AF855EC5C122A5948DB493E155E675AA25EEECC53288C0E33931403640BC5E5780994015A75FC929DAFED7A29
    IsCA: false
    SubjectKeyId: C9C25361669D5FAB25F426CD0F389AA849EA48A9
    AuthorityKeyId: 3DD350A5D6A0ADEEF34A600A65D321D4F8F8D60F
    DNSNames: github.com,www.github.com


    Subject: CN=DigiCert SHA2 Extended Validation Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US
    NotBefore: 2013-10-22 12:00:00 +0000 UTC
    NotAfter: 2028-10-22 12:00:00 +0000 UTC
    PublicKey: 30820122300D06092A864886F70D01010105000382010F003082010A0282010100D753A40451F899A616484B6727AA9349D039ED0CB0B00087F1672886858C8E63DABCB14038E2D3F5ECA50518B83D3EC5991732EC188CFAF10CA6642185CB071034B052882B1F689BD2B18F12B0B3D2E7881F1FEF387754535F80793F2E1AAAA81E4B2B0DABB763B935B77D14BC594BDF514AD2A1E20CE29082876AAEEAD764D69855E8FDAF1A506C54BC11F2FD4AF29DBB7F0EF4D5BE8E16891255D8C07134EEF6DC2DECC48725868DD821E4B04D0C89DC392617DDF6D79485D80421709D6F6FFF5CBA19E145CB5657287E1C0D4157AAB7B827BBB1E4FA2AEF2123751AAD2D9B86358C9C77B573ADD8942DE4F30C9DEEC14E627E17C0719E2CDEF1F9102819330203010001
    Version: 3
    Issuer: CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
    SerialNumber: 16582437038678467094619379592629788035
    PublicKeyAlgorithm: RSA
    SignatureAlgorithm: SHA256-RSA
    Signature: 9DB6D09086E18602EDC5A0F0341C74C18D76CC860AA8F04A8A42D63FC8A94DAD7C08ADE6B650B8A21A4D8807B12921DCE7DAC63C21E0E3114970AC7A1D01A4CA113A57AB7D572A4074FDD31D851850DF574775A17D55202E473750728C7F821BD2628F2D035ADAC3C8A1CE2C52A20063EB73BA71C84927239764859E380EAD63683CBA52815879A32C0CDFDE6DEB31F2BAA07C6CF12CD4E1BD77843703CE32B5C89A811A4A924E3B469A85FE83A2F99E8CA3CC0D5EB33DCF04788F14147B329CC700A65CC4B5A1558D5A5668A42270AA3C8171D99DA8453BF4E5F6A251DDC77B62E86F0C74EBB8DAF8BF870D795091909B183B915927F1352813AB267ED5F77A
    IsCA: true
    SubjectKeyId: 3DD350A5D6A0ADEEF34A600A65D321D4F8F8D60F
    AuthorityKeyId: B13EC36903F8BF4701D498261A0802EF63642BC3
```
