package providers

import (
	"context"

	"github.com/authorizerdev/authorizer/server/db/models"
	"github.com/authorizerdev/authorizer/server/graph/model"
)

type Provider interface {
	// AddUser to save user information in database
	AddUser(ctx context.Context, user models.User) (models.User, error)
	// UpdateUser to update user information in database
	UpdateUser(ctx context.Context, user models.User) (models.User, error)
	// DeleteUser to delete user information from database
	DeleteUser(ctx context.Context, user models.User) error
	// ListUsers to get list of users from database
	ListUsers(ctx context.Context, pagination model.Pagination) (*model.Users, error)
	// GetUserByEmail to get user information from database using email address
	GetUserByEmail(ctx context.Context, email string) (models.User, error)
	// GetCreatorByEmail to get creator information from database using email address
	GetCreatorByEmail(ctx context.Context, email string) (models.Creator, error)
	// GetVerifiedUserByEmail to get verified user information from database using email address
	GetVerifiedUserByEmail(ctx context.Context, email string) (models.User, error)
	// DeleteUnverifyEmailUsers to delete unverify users information from database
	DeleteUnverifyEmailUsers(ctx context.Context, email string) error
	// GetUserByWalletAddress to get user information from database using wallet address
	GetUserByWalletAddress(ctx context.Context, addresss string) (models.User, error)
	// GetUserByFbID to get user information from database using facebook Id
	GetUserByFbId(ctx context.Context, fbId string) (models.User, error)
	// GetUserByZaloID to get user information from database using facebook Id
	GetUserByZaloId(ctx context.Context, zaloId string) (models.User, error)
	// GetUserByPhoneNumber to get user information from database using phone number
	GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (*models.User, error)
	// GetUserByID to get user information from database using user ID
	GetUserByID(ctx context.Context, id string) (models.User, error)
	// UpdateUsers to update multiple users, with parameters of user IDs slice
	// If ids set to nil / empty all the users will be updated
	UpdateUsers(ctx context.Context, data map[string]interface{}, ids []string) error

	// AddVerification to save verification request in database
	AddVerificationRequest(ctx context.Context, verificationRequest models.VerificationRequest) (models.VerificationRequest, error)
	// GetVerificationRequestByToken to get verification request from database using token
	GetVerificationRequestByToken(ctx context.Context, token string) (models.VerificationRequest, error)
	// GetVerificationRequestByEmail to get verification request by email from database
	GetVerificationRequestByEmail(ctx context.Context, email string, identifier string) (models.VerificationRequest, error)
	// ListVerificationRequests to get list of verification requests from database
	ListVerificationRequests(ctx context.Context, pagination model.Pagination) (*model.VerificationRequests, error)
	// DeleteVerificationRequest to delete verification request from database
	DeleteVerificationRequest(ctx context.Context, verificationRequest models.VerificationRequest) error

	// AddSession to save session information in database
	AddSession(ctx context.Context, session models.Session) error

	// AddEnv to save environment information in database
	AddEnv(ctx context.Context, env models.Env) (models.Env, error)
	// UpdateEnv to update environment information in database
	UpdateEnv(ctx context.Context, env models.Env) (models.Env, error)
	// GetEnv to get environment information from database
	GetEnv(ctx context.Context) (models.Env, error)

	// AddWebhook to add webhook
	AddWebhook(ctx context.Context, webhook models.Webhook) (*model.Webhook, error)
	// UpdateWebhook to update webhook
	UpdateWebhook(ctx context.Context, webhook models.Webhook) (*model.Webhook, error)
	// ListWebhooks to list webhook
	ListWebhook(ctx context.Context, pagination model.Pagination) (*model.Webhooks, error)
	// GetWebhookByID to get webhook by id
	GetWebhookByID(ctx context.Context, webhookID string) (*model.Webhook, error)
	// GetWebhookByEventName to get webhook by event_name
	GetWebhookByEventName(ctx context.Context, eventName string) ([]*model.Webhook, error)
	// DeleteWebhook to delete webhook
	DeleteWebhook(ctx context.Context, webhook *model.Webhook) error

	// AddWebhookLog to add webhook log
	AddWebhookLog(ctx context.Context, webhookLog models.WebhookLog) (*model.WebhookLog, error)
	// ListWebhookLogs to list webhook logs
	ListWebhookLogs(ctx context.Context, pagination model.Pagination, webhookID string) (*model.WebhookLogs, error)

	// AddEmailTemplate to add EmailTemplate
	AddEmailTemplate(ctx context.Context, emailTemplate models.EmailTemplate) (*model.EmailTemplate, error)
	// UpdateEmailTemplate to update EmailTemplate
	UpdateEmailTemplate(ctx context.Context, emailTemplate models.EmailTemplate) (*model.EmailTemplate, error)
	// ListEmailTemplates to list EmailTemplate
	ListEmailTemplate(ctx context.Context, pagination model.Pagination) (*model.EmailTemplates, error)
	// GetEmailTemplateByID to get EmailTemplate by id
	GetEmailTemplateByID(ctx context.Context, emailTemplateID string) (*model.EmailTemplate, error)
	// GetEmailTemplateByEventName to get EmailTemplate by event_name
	GetEmailTemplateByEventName(ctx context.Context, eventName string) (*model.EmailTemplate, error)
	// DeleteEmailTemplate to delete EmailTemplate
	DeleteEmailTemplate(ctx context.Context, emailTemplate *model.EmailTemplate) error

	// UpsertOTP to add or update otp
	UpsertOTP(ctx context.Context, otp *models.OTP) (*models.OTP, error)
	// GetOTPByEmail to get otp for a given email address
	GetOTPByEmail(ctx context.Context, emailAddress string) (*models.OTP, error)
	// DeleteOTP to delete otp
	DeleteOTP(ctx context.Context, otp *models.OTP) error
}
