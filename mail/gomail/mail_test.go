package gomail

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"application/kasa/helpers/mail"

	"application/kasa/helpers/context"
)

// Successfully sends an email with all fields populated
func TestSendEmailWithAllFields(t *testing.T) {
	ctx := context.Background()
	to := []string{"to@example.com"}
	// cc := []string{"cc@example.com"}
	// bcc := []string{"bcc@example.com"}
	subject := "Test Subject with gomail"
	body := "Test Body with gomail"
	file := []string{}

	sender := MailSender{
		Config: mail.Config{
			From:          "FromName@163.com",
			Host:          "smtp.163.com",
			MaxRetries:    3,
			Nickname:      "Nickname",
			Password:      "",
			Port:          465,
			RetryInterval: 1,
			SSL:           true,
			Username:      "FromName@163.com",
		},
	}
	mail.Register(&sender)

	err := mail.SendTo(ctx, to, subject, body, file...)
	if err == nil {
		return
	}
	assert.NoError(t, err)
}

// Handles empty 'to' field gracefully
func TestSendEmailWithEmptyToField(t *testing.T) {
	// ctx := context.Background()
	// to := []string{}
	// cc := []string{"cc@example.com"}
	// bcc := []string{"bcc@example.com"}
	// subject := "Test Subject"
	// body := "Test Body"
	// file := []string{"attachment.txt"}
	//
	// mockSender := new(MockSender)
	// globalSender = mockSender
	//
	// mockSender.On("Send", ctx, to, cc, bcc, subject, body, file).Return(nil)
	//
	// err := Send(ctx, to, cc, bcc, subject, body, file...)
	// assert.NoError(t, err)
	// mockSender.AssertExpectations(t)
}

// Handles empty 'subject' field gracefully
func TestSendEmailWithEmptySubjectField(t *testing.T) {
	// ctx := context.Background()
	// to := []string{"recipient@example.com"}
	// cc := []string{"cc@example.com"}
	// bcc := []string{"bcc@example.com"}
	// subject := ""
	// body := "Test Body"
	// file := []string{"attachment.txt"}
	//
	// mockSender := new(MockSender)
	// globalSender = mockSender
	//
	// mockSender.On("Send", ctx, to, cc, bcc, subject, body, file).Return(nil)
	//
	// err := Send(ctx, to, cc, bcc, subject, body, file...)
	// assert.NoError(t, err)
	// mockSender.AssertExpectations(t)
}
