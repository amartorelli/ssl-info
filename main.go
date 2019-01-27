package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

type certInfo map[string]string

func parseCert(cert *x509.Certificate) (certInfo, error) {
	c := make(certInfo, 0)

	// signature
	dst := make([]byte, hex.EncodedLen(len(cert.Signature)))
	hex.Encode(dst, cert.Signature)
	c["Signature"] = strings.ToUpper(string(dst))

	c["SignatureAlgorithm"] = cert.SignatureAlgorithm.String()

	c["PublicKeyAlgorithm"] = cert.PublicKeyAlgorithm.String()
	// pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	// if err != nil {
	// 	return nil, err
	// }

	// dst = make([]byte, hex.EncodedLen(len(pub)))
	// hex.Encode(dst, pub)
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		logrus.Error("this is RSA")
		pub := cert.PublicKey.(*rsa.PublicKey)
		logrus.Error(pub.N)
		// c["PublicKey"] = strings.ToUpper(string(pub.N))
	case *ecdsa.PublicKey:
		logrus.Error("this is ECDSA")
		pub := cert.PublicKey.(*ecdsa.PublicKey)
		x := hex.EncodeToString([]byte(pub.X.String()))
		logrus.Errorf("x: %s", x)
		y := hex.EncodeToString([]byte(pub.Y.String()))
		logrus.Errorf("y: %s", y)
		// c["PublicKey"] = strings.ToUpper(string(pub.X))
	default:
		fmt.Println("it's something else")
	}

	c["Version"] = strconv.FormatInt(int64(cert.Version), 10)
	c["SerialNumber"] = cert.SerialNumber.String()
	c["Issuer"] = cert.Issuer.String()
	c["Subject"] = cert.Subject.String()
	c["NotBefore"] = cert.NotBefore.String()
	c["NotAfter"] = cert.NotAfter.String()
	c["IsCA"] = strconv.FormatBool(cert.IsCA)

	// SubjectKeyId
	dst = make([]byte, hex.EncodedLen(len(cert.SubjectKeyId)))
	hex.Encode(dst, cert.SubjectKeyId)
	c["SubjectKeyId"] = strings.ToUpper(string(dst))

	// AuthorityKeyId
	dst = make([]byte, hex.EncodedLen(len(cert.AuthorityKeyId)))
	hex.Encode(dst, cert.AuthorityKeyId)
	c["AuthorityKeyId"] = strings.ToUpper(string(dst))

	if len(cert.DNSNames) > 0 {
		c["DNSNames"] = strings.Join(cert.DNSNames, ",")
	}

	if len(cert.EmailAddresses) > 0 {
		c["EmailAddresses"] = strings.Join(cert.EmailAddresses, ",")
	}

	// IPAddresses
	ips := make([]string, 0)
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	if len(ips) > 0 {
		c["IPAddresses"] = strings.Join(ips, ",")
	}

	// URIs
	uris := make([]string, 0)
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}
	if len(uris) > 0 {
		c["URIs"] = strings.Join(uris, ",")
	}

	if len(cert.CRLDistributionPoints) > 0 {
		c["CRLDistributionPoints"] = strings.Join(cert.CRLDistributionPoints, ",")
	}

	return c, nil
}

func (ci certInfo) String() string {
	certInfoStr := make([]string, 0)
	order := []string{"Subject", "NotBefore", "NotAfter", "PublicKeyAlgorithm", "PublicKey", "Version", "Issuer", "SerialNumber", "SignatureAlgorithm", "Signature", "IsCA", "SubjectKeyId", "AuthorityKeyId", "DNSNames", "EmailAddresses", "IPAddresses", "URIs"}
	for _, o := range order {
		val, ok := ci[o]
		if ok {
			certInfoStr = append(certInfoStr, fmt.Sprintf("    %s: %s\n", o, val))
		}
	}
	return strings.Join(certInfoStr, "")
}

func parseCerts(certs []*x509.Certificate) (string, error) {
	o := make([]string, 0)
	for _, c := range certs {
		co, err := parseCert(c)
		if err != nil {
			return "", err
		}
		o = append(o, co.String())
	}
	return strings.Join(o, "\n\n"), nil
}

type tlsInfo map[string]string

func getTLSInfo(cs tls.ConnectionState) (tlsInfo, error) {
	info := make(map[string]string, 0)
	info["Version"] = strconv.FormatInt(int64(cs.Version), 10)
	info["HandshakeComplete"] = strconv.FormatBool(cs.HandshakeComplete)
	info["CipherSuite"] = strconv.FormatInt(int64(cs.CipherSuite), 10)
	info["ServerName"] = cs.ServerName

	// certs
	peerCerts, err := parseCerts(cs.PeerCertificates)
	if err != nil {
		return info, err
	}
	if len(peerCerts) > 0 {
		info["PeerCertificates"] = fmt.Sprintf("\n%s", peerCerts)
	}

	// parse verified chains
	// verifiedChainsCerts, err := parseCerts(cs.VerifiedChains)
	// if err != nil {
	// 	return info, err
	// }
	// info["PeerCertificates"] = fmt.Sprintf("\n%v", peerCerts)

	return info, nil
}

func (ti tlsInfo) String() string {
	tlsInfoStr := make([]string, 0)
	order := []string{"Servername", "Version", "ChipherSuite", "HandshakeComplete", "PeerCertificates"}
	for _, o := range order {
		val, ok := ti[o]
		if ok {
			tlsInfoStr = append(tlsInfoStr, fmt.Sprintf("%s: %s\n", o, val))
		}
	}
	return strings.Join(tlsInfoStr, "")
}

func main() {
	// init logging

	// flags
	endpoint := flag.String("host", "", "the host to connect to")
	port := flag.String("port", "443", "the port to use")
	flag.Parse()

	if *endpoint == "" {
		logrus.Fatal("unspecified endpoint")
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", *endpoint, *port), &tls.Config{})
	if err != nil {
		logrus.Fatal(err)
	}
	defer conn.Close()

	// get ConnectionState
	cs := conn.ConnectionState()
	info, err := getTLSInfo(cs)
	if err != nil {
		logrus.Fatal(err)
	}

	fmt.Println(info.String())
}
