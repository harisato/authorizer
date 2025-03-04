package resolvers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/authorizerdev/authorizer/server/constants"
	"github.com/authorizerdev/authorizer/server/cookie"
	"github.com/authorizerdev/authorizer/server/db"
	"github.com/authorizerdev/authorizer/server/db/models"
	"github.com/authorizerdev/authorizer/server/graph/model"
	"github.com/authorizerdev/authorizer/server/memorystore"
	"github.com/authorizerdev/authorizer/server/refs"
	"github.com/authorizerdev/authorizer/server/token"
	"github.com/authorizerdev/authorizer/server/utils"
	"github.com/authorizerdev/authorizer/server/validators"
)

// MobileLoginResolver is a resolver for mobile login mutation
func MobileLoginResolver(ctx context.Context, params model.MobileLoginInput) (*model.AuthResponse, error) {
	var res *model.AuthResponse

	gc, err := utils.GinContextFromContext(ctx)
	if err != nil {
		log.Debug("Failed to get GinContext: ", err)
		return res, err
	}

	isBasiAuthDisabled, err := memorystore.Provider.GetBoolStoreEnvVariable(constants.EnvKeyDisableMobileBasicAuthentication)
	if err != nil {
		log.Debug("Error getting mobile basic auth disabled: ", err)
		isBasiAuthDisabled = true
	}

	if isBasiAuthDisabled {
		log.Debug("Basic authentication is disabled.")
		return res, fmt.Errorf(`phone number based basic authentication is disabled for this instance`)
	}

	log := log.WithFields(log.Fields{
		"phone_number": params.PhoneNumber,
	})

	user, err := db.Provider.GetUserByPhoneNumber(ctx, params.PhoneNumber)
	if err != nil {
		log.Debug("Failed to get user by phone number: ", err)
		return res, fmt.Errorf(`bad user credentials`)
	}

	if user.RevokedTimestamp != nil {
		log.Debug("User access is revoked")
		return res, fmt.Errorf(`user access has been revoked`)
	}

	if !strings.Contains(user.SignupMethods, constants.AuthRecipeMethodMobileBasicAuth) {
		log.Debug("User signup method is not mobile basic auth")
		return res, fmt.Errorf(`user has not signed up with phone number & password`)
	}

	if user.PhoneNumberVerifiedAt == nil {
		log.Debug("User phone number is not verified")
		return res, fmt.Errorf(`phone number is not verified`)
	}

	err = bcrypt.CompareHashAndPassword([]byte(*user.Password), []byte(params.Password))

	if err != nil {
		log.Debug("Failed to compare password: ", err)
		return res, fmt.Errorf(`bad user credentials`)
	}

	defaultRolesString, err := memorystore.Provider.GetStringStoreEnvVariable(constants.EnvKeyDefaultRoles)
	roles := []string{}
	if err != nil {
		log.Debug("Error getting default roles: ", err)
		defaultRolesString = ""
	} else {
		roles = strings.Split(defaultRolesString, ",")
	}

	currentRoles := strings.Split(user.Roles, ",")
	if len(params.Roles) > 0 {
		if !validators.IsValidRoles(params.Roles, currentRoles) {
			log.Debug("Invalid roles: ", params.Roles)
			return res, fmt.Errorf(`invalid roles`)
		}

		roles = params.Roles
	}

	creator, err := db.Provider.GetCreatorByEmail(ctx, user.Email)
	fmt.Println(creator)
	if err == nil {
		roles = append(roles, "creator")
		user.Roles = strings.Join(roles, ",")
	}

	scope := []string{"openid", "email", "profile"}
	if params.Scope != nil && len(scope) > 0 {
		scope = params.Scope
	}

	/*
		// TODO use sms authentication for MFA
		isEmailServiceEnabled, err := memorystore.Provider.GetBoolStoreEnvVariable(constants.EnvKeyIsEmailServiceEnabled)
		if err != nil || !isEmailServiceEnabled {
			log.Debug("Email service not enabled: ", err)
		}

		isMFADisabled, err := memorystore.Provider.GetBoolStoreEnvVariable(constants.EnvKeyDisableMultiFactorAuthentication)
		if err != nil || !isEmailServiceEnabled {
			log.Debug("MFA service not enabled: ", err)
		}

		// If email service is not enabled continue the process in any way
		if refs.BoolValue(user.IsMultiFactorAuthEnabled) && isEmailServiceEnabled && !isMFADisabled {
			otp := utils.GenerateOTP()
			otpData, err := db.Provider.UpsertOTP(ctx, &models.OTP{
				Email:     user.Email,
				Otp:       otp,
				ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
			})
			if err != nil {
				log.Debug("Failed to add otp: ", err)
				return nil, err
			}

			go func() {
				// exec it as go routine so that we can reduce the api latency
				go email.SendEmail([]string{params.PhoneNumber}, constants.VerificationTypeOTP, map[string]interface{}{
					"user":         user.ToMap(),
					"organization": utils.GetOrganization(),
					"otp":          otpData.Otp,
				})
				if err != nil {
					log.Debug("Failed to send otp email: ", err)
				}
			}()

			return &model.AuthResponse{
				Message:             "Please check the OTP in your inbox",
				ShouldShowOtpScreen: refs.NewBoolRef(true),
			}, nil
		}
	*/

	code := ""
	codeChallenge := ""
	nonce := ""
	if params.State != nil {
		// Get state from store
		authorizeState, _ := memorystore.Provider.GetState(refs.StringValue(params.State))
		if authorizeState != "" {
			authorizeStateSplit := strings.Split(authorizeState, "@@")
			if len(authorizeStateSplit) > 1 {
				code = authorizeStateSplit[0]
				codeChallenge = authorizeStateSplit[1]
			} else {
				nonce = authorizeState
			}
			go memorystore.Provider.RemoveState(refs.StringValue(params.State))
		}
	}

	if nonce == "" {
		nonce = uuid.New().String()
	}

	authToken, err := token.CreateAuthToken(gc, *user, roles, scope, constants.AuthRecipeMethodMobileBasicAuth, nonce, code)
	if err != nil {
		log.Debug("Failed to create auth token", err)
		return res, err
	}

	// TODO add to other login options as well
	// Code challenge could be optional if PKCE flow is not used
	if code != "" {
		if err := memorystore.Provider.SetState(code, codeChallenge+"@@"+authToken.FingerPrintHash); err != nil {
			log.Debug("SetState failed: ", err)
			return res, err
		}
	}

	expiresIn := authToken.AccessToken.ExpiresAt - time.Now().Unix()
	if expiresIn <= 0 {
		expiresIn = 1
	}

	res = &model.AuthResponse{
		Message:     `Logged in successfully`,
		AccessToken: &authToken.AccessToken.Token,
		IDToken:     &authToken.IDToken.Token,
		ExpiresIn:   &expiresIn,
		User:        user.AsAPIUser(),
	}

	cookie.SetSession(gc, authToken.FingerPrintHash)
	sessionStoreKey := constants.AuthRecipeMethodMobileBasicAuth + ":" + user.ID
	memorystore.Provider.SetUserSession(sessionStoreKey, constants.TokenTypeSessionToken+"_"+authToken.FingerPrint, authToken.FingerPrintHash, authToken.SessionTokenExpiresAt)
	memorystore.Provider.SetUserSession(sessionStoreKey, constants.TokenTypeAccessToken+"_"+authToken.FingerPrint, authToken.AccessToken.Token, authToken.AccessToken.ExpiresAt)

	if authToken.RefreshToken != nil {
		res.RefreshToken = &authToken.RefreshToken.Token
		memorystore.Provider.SetUserSession(sessionStoreKey, constants.TokenTypeRefreshToken+"_"+authToken.FingerPrint, authToken.RefreshToken.Token, authToken.RefreshToken.ExpiresAt)
	}

	go func() {
		utils.RegisterEvent(ctx, constants.UserLoginWebhookEvent, constants.AuthRecipeMethodMobileBasicAuth, *user)
		db.Provider.AddSession(ctx, models.Session{
			UserID:    user.ID,
			UserAgent: utils.GetUserAgent(gc.Request),
			IP:        utils.GetIP(gc.Request),
		})
	}()

	return res, nil
}
