/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package email provides a email client
package email

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"time"

	"github.com/jordan-wright/email"
	"github.com/origadmin/runtime/context"

	configv1 "github.com/origadmin/runtime/gen/go/config/v1"
	"github.com/origadmin/runtime/mail"
)

type MailSender struct {
	*configv1.Mail
}

func init() {
	mail.Register(NewMailSender)
}

// Send smtp client send email
func (s *MailSender) Send(ctx context.Context, to []string, cc []string, bcc []string, subject string, body string, file ...string) error {
	from := s.From
	if s.Nickname != "" {
		from = fmt.Sprintf("%s <%s>", s.Nickname, from)
	}

	auth := smtp.PlainAuth("", from, s.Password, s.Host)
	e := email.NewEmail()
	e.From = from
	e.To = to
	e.Subject = subject
	e.HTML = []byte(body)
	var err error
	hostAddr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	if s.Ssl {
		err = e.SendWithTLS(hostAddr, auth, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: s.Host,
		})
	} else {
		err = e.Send(hostAddr, auth)
	}
	return err
}

// SendTo smtp client send email, use to specify recipients
func (s *MailSender) SendTo(ctx context.Context, to []string, subject string, body string, file ...string) error {
	var err error
	for i := int32(0); i < s.MaxRetries; i++ {
		err = s.Send(ctx, to, nil, nil, subject, body, file...)
		if err == nil {
			break
		}
		if interval := s.GetRetryInterval(); interval != nil && interval.AsDuration() > 0 {
			time.Sleep(interval.AsDuration())
		} else {
			return err
		}
		continue
	}
	return err
}

func NewMailSender(cfg *configv1.Mail) mail.Sender {
	if cfg == nil {
		cfg = new(configv1.Mail)
	}
	return &MailSender{Mail: cfg}
}

var _ mail.Sender = (*MailSender)(nil)
