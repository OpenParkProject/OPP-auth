package otp

import (
	"fmt"
	"math/rand"
	"time"
)

const OTP_EXPIRATION_TIME = 15 * time.Minute

func GenerateOTP() (string, time.Time, error) {
	// Generate a random OTP (6 digits)
	otp := fmt.Sprintf("%06d", rand.Intn(1000000))
	exp_date := time.Now().Add(OTP_EXPIRATION_TIME)
	return otp, exp_date, nil
}

func ValidateOTP(otp string, expDate time.Time) (bool, error) {
	if time.Now().After(expDate) {
		return false, fmt.Errorf("OTP has expired")
	}
	return true, nil
}
