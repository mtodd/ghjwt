package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var iss = 0
var now = time.Now()
var defaultIat = int(now.Unix())
var iat = defaultIat
var defaultDur = 10 * time.Minute
var dur = defaultDur
var defaultExp = int(now.Add(defaultDur).Unix())
var exp = defaultExp
var alg = "RS256"
var pemPath = ""

func main() {
	flag.IntVar(&iss, "iss", iss, "required: the GitHub App ID")
	flag.IntVar(&iat, "iat", defaultIat, "the unixtime this JWT was issued at (defaults to now)")
	flag.IntVar(&exp, "exp", defaultExp, "the unixtime this JWT will expire")
	flag.DurationVar(&dur, "dur", dur, "the number of milliseconds this JWT is valid before it expires")
	flag.StringVar(&alg, "alg", alg, "the signing algorithm")
	flag.StringVar(&pemPath, "pem", pemPath, "required: the pem file used for signing JWTs")

	flag.Parse()

	if iss == 0 {
		fmt.Fprintf(os.Stderr, "iss issuer ID is required")
		flag.Usage()
		os.Exit(1)
	}

	if pemPath == "" {
		fmt.Fprintf(os.Stderr, "pem path is required")
		flag.Usage()
		os.Exit(1)
	}

	pem, err := ioutil.ReadFile(pemPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		flag.Usage()
		os.Exit(1)
	}

	pk, err := jwt.ParseRSAPrivateKeyFromPEM(pem)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		flag.Usage()
		os.Exit(1)
	}

	if alg == "" {
		fmt.Fprintf(os.Stderr, "algorithm is required")
		flag.Usage()
		os.Exit(1)
	}

	method := jwt.GetSigningMethod(alg)
	if method == nil {
		fmt.Fprintf(os.Stderr, "signing method algorithm specified (%s) could not be found", alg)
		flag.Usage()
		os.Exit(1)
	}

	if dur != defaultDur && exp != defaultExp {
		fmt.Fprintf(os.Stderr, "either specify -dur or -exp, not both")
		flag.Usage()
		os.Exit(1)
	}

	// if expiration wasn't explicitly given, calculate expiration using duration
	if exp == defaultExp {
		// if iat is given, parse its time value so we can calculate expiration
		if iat != defaultIat {
			now = time.Unix(int64(iat), 0)
		}

		exp = int(now.Add(dur).Unix())
	}

	claims := make(jwt.MapClaims)

	claims["iss"] = iss
	claims["iat"] = iat
	claims["exp"] = exp

	err = claims.Valid()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		flag.Usage()
		os.Exit(1)
	}

	tok := jwt.NewWithClaims(method, claims)

	signed, err := tok.SignedString(pk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println(signed)
}
