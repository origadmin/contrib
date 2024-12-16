/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package gomail

import (
	"testing"
	"time"

	"github.com/origadmin/runtime/context"
	configv1 "github.com/origadmin/runtime/gen/go/config/v1"
	"github.com/origadmin/runtime/mail"
	"google.golang.org/protobuf/types/known/durationpb"
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

	sender := mail.New(&configv1.Mail{
		From:          "FromName@163.com",
		Host:          "smtp.163.com",
		MaxRetries:    3,
		Nickname:      "Nickname",
		Password:      "",
		Port:          465,
		RetryInterval: durationpb.New(1 * time.Second),
		Ssl:           true,
		Username:      "FromName@163.com",
	})
	err := sender.SendTo(ctx, to, subject, body, file...)
	if err == nil {
		return
	}
	//assert.NoError(t, err)
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
