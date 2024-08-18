package verification

import (
	"fmt"
	"log/slog"
	"net/smtp"
	"time"

	le "github.com/kuromii5/sync-auth/pkg/logger/l_err"
)

type VerificationManager struct {
	log         *slog.Logger
	CodeTTL     time.Duration
	appEmail    string
	appPassword string
}

func NewVerificationManager(
	log *slog.Logger,
	CodeTTL time.Duration,
	appEmail string,
	appPassword string,
) *VerificationManager {
	return &VerificationManager{
		log:         log,
		CodeTTL:     CodeTTL,
		appEmail:    appEmail,
		appPassword: appPassword,
	}
}

func (v *VerificationManager) SendCode(email string, code int32) error {
	const f = "verification.SendCode"

	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	auth := smtp.PlainAuth("", v.appEmail, v.appPassword, smtpHost)

	from := v.appEmail
	to := []string{email}
	subject := "Email Verification Code"
	body := fmt.Sprintf("Your verification code is: %d\nThis code is valid for %s.", code, v.CodeTTL)
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", email, subject, body))

	err := smtp.SendMail(fmt.Sprintf("%s:%s", smtpHost, smtpPort), auth, from, to, msg)
	if err != nil {
		v.log.Error("Failed to send verification email", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	v.log.Info("verification code sent to email", slog.String("email", email))

	return nil
}
