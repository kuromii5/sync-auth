package transport

import (
	"context"
	"errors"

	auth "github.com/kuromii5/sync-auth/api/sync-auth/v1"
	"github.com/kuromii5/sync-auth/internal/models"
	"github.com/kuromii5/sync-auth/internal/repo/redis"
	"github.com/kuromii5/sync-auth/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type api struct {
	auth.UnimplementedAuthServer
	auth *service.Auth
}

type Auth interface {
	SignUp(ctx context.Context, email, password string) (int32, error)
	Login(ctx context.Context, email, password, fingerprint string) (models.TokenPair, error)
	Logout(ctx context.Context, accessToken, fingerprint string) error

	ExchangeCodeForToken(ctx context.Context, code, provider string) (models.TokenPair, error)

	VerifyEmail(ctx context.Context, accessToken string) (models.VerifyEmailResp, error)
	ConfirmCode(ctx context.Context, code int32, accessToken string) (models.ConfirmCodeResp, error)

	GetAccessToken(ctx context.Context, refreshToken, fingerprint string) (string, error)
	ValidateAccessToken(ctx context.Context, token string) (int32, error)
}

func NewGrpcServer(authApi *service.Auth) *grpc.Server {
	api := &api{auth: authApi}

	grpc := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	reflection.Register(grpc)
	auth.RegisterAuthServer(grpc, api)

	return grpc
}

func (a *api) SignUp(ctx context.Context, req *auth.SignUpRequest) (*auth.AuthResponse, error) {
	err := validateSignUpRequest(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	_, err = a.auth.SignUp(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "internal register error")
	}

	// automatically log in after register
	tokens, err := a.auth.Login(ctx, req.GetEmail(), req.GetPassword(), req.GetFingerprint())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal login error")
	}

	return &auth.AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (a *api) Login(ctx context.Context, req *auth.LoginRequest) (*auth.AuthResponse, error) {
	err := validateLoginRequest(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// get the pair of tokens: access and refresh
	tokens, err := a.auth.Login(ctx, req.GetEmail(), req.GetPassword(), req.GetFingerprint())
	if err != nil {
		if errors.Is(err, service.ErrInvalidCreds) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}

		return nil, status.Error(codes.Internal, "internal login error")
	}

	return &auth.AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (a *api) Logout(ctx context.Context, req *auth.LogoutRequest) (*auth.LogoutResponse, error) {
	if err := a.auth.Logout(ctx, req.GetAccessToken(), req.GetFingerprint()); err != nil {
		return nil, status.Error(codes.Internal, "failed to log out")
	}

	return &auth.LogoutResponse{}, nil
}

func (a *api) VerifyEmail(ctx context.Context, req *auth.VerifyEmailRequest) (*auth.VerifyEmailResponse, error) {
	response, err := a.auth.VerifyEmail(ctx, req.GetAccessToken())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &auth.VerifyEmailResponse{
		Status:  response.Status,
		CodeTTL: int32(response.CodeTTL.Seconds()),
	}, nil
}

func (a *api) ConfirmCode(ctx context.Context, req *auth.ConfirmCodeRequest) (*auth.ConfirmCodeResponse, error) {
	response, err := a.auth.ConfirmCode(ctx, req.GetCode(), req.GetAccessToken())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &auth.ConfirmCodeResponse{
		Success: response.Success,
		Message: response.Message,
	}, nil
}

func (a *api) ExchangeCodeForToken(ctx context.Context, req *auth.ExchangeCodeRequest) (*auth.AuthResponse, error) {
	tokens, err := a.auth.ExchangeCodeForToken(ctx, req.GetCode(), req.GetProvider(), req.GetFingerprint())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &auth.AuthResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (a *api) GetAccessToken(ctx context.Context, req *auth.GetATRequest) (*auth.GetATResponse, error) {
	accessToken, err := a.auth.GetAccessToken(ctx, req.GetRefreshToken(), req.GetFingerprint())
	if err != nil {
		if errors.Is(err, redis.ErrTokenNotFound) {
			return nil, status.Error(codes.NotFound, "the refresh token does not exist")
		}

		return nil, status.Error(codes.Internal, "failed to generate access token")
	}

	return &auth.GetATResponse{
		AccessToken: accessToken,
	}, nil
}

func (a *api) ValidateAccessToken(ctx context.Context, req *auth.ValidateATRequest) (*auth.ValidateATResponse, error) {
	userID, err := a.auth.ValidateAccessToken(ctx, req.GetAccessToken())
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &auth.ValidateATResponse{
		UserId: userID,
	}, nil
}
