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
	appSmtpHost string
}

func NewVerificationManager(
	log *slog.Logger,
	CodeTTL time.Duration,
	appEmail, appPassword, appSmtpHost string,
) *VerificationManager {
	return &VerificationManager{
		log:         log,
		CodeTTL:     CodeTTL,
		appEmail:    appEmail,
		appPassword: appPassword,
		appSmtpHost: appSmtpHost,
	}
}

func (v *VerificationManager) SendCode(email string, code int32) error {
	const f = "verification.SendCode"

	smtpPort := "587"

	auth := smtp.PlainAuth("", v.appEmail, v.appPassword, v.appSmtpHost)

	from := v.appEmail
	to := []string{email}

	subject := "Email Verification Code"
	body := fmt.Sprintf("Your verification code is: %d\nThis code is valid for %s.", code, v.CodeTTL)
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s", email, subject, body))

	err := smtp.SendMail(fmt.Sprintf("%s:%s", v.appSmtpHost, smtpPort), auth, from, to, msg)
	if err != nil {
		v.log.Error("Failed to send verification email", le.Err(err))

		return fmt.Errorf("%s:%w", f, err)
	}

	v.log.Info("verification code sent to email", slog.String("email", email))

	return nil
}
