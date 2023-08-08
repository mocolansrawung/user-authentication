package user

import (
	"github.com/evermos/boilerplate-go/configs"
	"github.com/evermos/boilerplate-go/shared"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserService interface {
	RegisterUser(registerRequestFormat RegisterRequestFormat) (ur UserRegister, err error)
	Login(loginRequestFormat LoginRequestFormat) (userLogin UserLogin, err error)
}

type UserServiceImpl struct {
	UserRepository UserRepository
	Config         *configs.Config
}

func ProvideUserServiceImpl(userRepository UserRepository, config *configs.Config) *UserServiceImpl {
	s := new(UserServiceImpl)
	s.UserRepository = userRepository
	s.Config = config

	return s
}

func (s *UserServiceImpl) RegisterUser(registerRequestFormat RegisterRequestFormat) (userRegister UserRegister, err error) {
	userRegister, err = userRegister.NewUserFromRequestFormat(registerRequestFormat)
	if err != nil {
		return
	}

	if err != nil {
		return userRegister, failure.BadRequest(err)
	}

	err = s.UserRepository.CreateUser(userRegister)
	if err != nil {
		return
	}

	accessToken, err := s.createToken(userRegister.ID, userRegister.Username, userRegister.Email)
	if err != nil {
		return
	}

	userRegister.AccessToken = accessToken

	return
}

func (s *UserServiceImpl) Login(loginRequestFormat LoginRequestFormat) (userLogin UserLogin, err error) {
	loginRequest, err := userLogin.LoginUserFromRequestFormat(loginRequestFormat)
	if err != nil {
		return
	}

	if err != nil {
		return userLogin, failure.BadRequest(err)
	}

	userLogin, err = s.UserRepository.ResolveLoginByUsername(loginRequest.Username)
	if err != nil {
		userLogin, err = s.UserRepository.ResolveLoginByEmail(loginRequest.Email)
		if err != nil {
			return userLogin, failure.BadRequest(err)
		}
	}

	isValidPassword := checkPasswordHash(loginRequest.Password, userLogin.Password)
	if !isValidPassword {
		return userLogin, failure.BadRequest(err)
	}

	accessToken, err := s.createToken(userLogin.ID, userLogin.Username, userLogin.Email)
	if err != nil {
		return
	}

	userLogin.AccessToken = accessToken

	return
}

// Internal Functions
func (s *UserServiceImpl) createToken(ID uuid.UUID, username string, email string) (accessToken string, err error) {
	jwtService := shared.ProvideJWTService(s.Config.App.Secret)
	accessToken, err = jwtService.GenerateJWT(ID, username, email)
	if err != nil {
		return
	}

	return
}

func checkPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
