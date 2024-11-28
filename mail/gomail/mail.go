/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package gomail provides a smtp email client
package gomail

import (
	"crypto/tls"
	"errors"
	"io"
	"time"

	"gopkg.in/gomail.v2"

	configv1 "github.com/origadmin/runtime/gen/go/config/v1"
	"github.com/origadmin/runtime/mail"
	
)

// MailSender is a smtp email client
type MailSender struct {
	*configv1.Mail
}

func init() {
	mail.Register(NewMailSender)
}

// Send smtp client send email
func (s *MailSender) Send(ctx context.Context, to []string, cc []string, bcc []string, subject string, body string, file ...string) error {
	msg := gomail.NewMessage(gomail.SetEncoding(gomail.Base64))
	msg.SetHeader("From", msg.FormatAddress(s.From, s.Nickname))
	msg.SetHeader("To", to...)
	msg.SetHeader("Cc", cc...)
	msg.SetHeader("Bcc", bcc...)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html;charset=utf-8", body)

	for _, v := range file {
		msg.Attach(v)
	}
	dail := gomail.Dialer{
		Host:     s.Host,
		Port:     int(s.Port),
		Username: s.Username,
		Password: s.Password,
		SSL:      s.Ssl,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: s.Host,
		},
	}
	sender, err := dail.Dial()
	if err != nil {
		return err
	}
	defer sender.Close()
	err = gomail.Send(sender, msg)
	if err != nil {
		return err
	}
	return nil
}

// SendTo smtp client send email, use to specify recipients
func (s *MailSender) SendTo(ctx context.Context, to []string, subject string, body string, file ...string) error {
	var err error
	for i := int32(0); i < s.MaxRetries; i++ {
		err = s.Send(ctx, to, nil, nil, subject, body, file...)
		if err == nil || errors.Is(err, io.EOF) {
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
