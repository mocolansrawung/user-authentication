package user

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/evermos/boilerplate-go/shared"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/evermos/boilerplate-go/shared/nuuid"
	"github.com/gofrs/uuid"
	"github.com/guregu/null"
	"golang.org/x/crypto/bcrypt"
)

// User: For Update and Get

type User struct {
	ID        uuid.UUID   `db:"id" validate:"required"`
	Name      string      `db:"name" validate:"required"`
	Username  string      `db:"username" validate:"required"`
	Password  string      `db:"password" validate:"required"`
	Email     string      `db:"email" validate:"required"`
	CreatedAt time.Time   `db:"created_at" validate:"required"`
	CreatedBy uuid.UUID   `db:"created_by" validate:"required"`
	UpdatedAt null.Time   `db:"updated_at"`
	UpdatedBy nuuid.NUUID `db:"updated_by"`
	DeletedAt null.Time   `db:"deleted_at"`
	DeletedBy nuuid.NUUID `db:"deleted_by"`
}

func (u *User) IsDeleted() (deleted bool) {
	return u.DeletedAt.Valid && u.DeletedBy.Valid
}

func (u User) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.ToResponseFormat())
}

func (u *User) Validate() (err error) {
	validator := shared.GetValidator()
	return validator.Struct(u)
}

func (u User) ToResponseFormat() UserResponseFormat {
	resp := UserResponseFormat{
		ID:        u.ID,
		Username:  u.Username,
		Name:      u.Name,
		CreatedBy: u.CreatedBy,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
		UpdatedBy: u.UpdatedBy.Ptr(),
		DeletedAt: u.DeletedAt,
		DeletedBy: u.DeletedBy.Ptr(),
	}

	return resp
}

type UserRequestFormat struct {
	// validate still not sure, it's not mandatory in GET
	Name string `json:"name" validate:"required"`
}

type UserResponseFormat struct {
	ID        uuid.UUID  `json:"id"`
	Username  string     `json:"username"`
	Name      string     `json:"name"`
	Email     string     `json:"email"`
	CreatedAt time.Time  `json:"createdAt"`
	CreatedBy uuid.UUID  `json:"createdBy"`
	UpdatedAt null.Time  `json:"updatedAt"`
	UpdatedBy *uuid.UUID `json:"updatedBy"`
	DeletedAt null.Time  `json:"deletedAt,omitempty"`
	DeletedBy *uuid.UUID `json:"deletedBy,omitempty"`
}

// Register

type UserRegister struct {
	ID          uuid.UUID   `db:"id" validate:"required"`
	Name        string      `db:"name" validate:"required"`
	Username    string      `db:"username" validate:"required"`
	Password    string      `db:"password" validate:"required"`
	Email       string      `db:"email" validate:"required"`
	AccessToken string      `db:"-"`
	CreatedAt   time.Time   `db:"created_at"`
	CreatedBy   uuid.UUID   `db:"created_by"`
	UpdatedAt   null.Time   `db:"updated_at"`
	UpdatedBy   nuuid.NUUID `db:"updated_by"`
	DeletedAt   null.Time   `db:"deleted_at"`
	DeletedBy   nuuid.NUUID `db:"deleted_by"`
}

func (ur *UserRegister) IsDeleted() (deleted bool) {
	return ur.DeletedAt.Valid && ur.DeletedBy.Valid
}

func (ur UserRegister) MarshalJSON() ([]byte, error) {
	return json.Marshal(ur.ToResponseFormat())
}

func (ur UserRegister) NewUserFromRequestFormat(req RegisterRequestFormat) (newUser UserRegister, err error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		failure.InternalError(err)
		return
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(req.Email) {
		err = errors.New("invalid email format")
		return
	}

	hashedPassword := string(bytes)
	userID, err := uuid.NewV4()
	if err != nil {
		failure.InternalError(err)
		return
	}

	newUser = UserRegister{
		ID:        userID,
		Name:      req.Name,
		Username:  req.Username,
		Email:     req.Email,
		Password:  hashedPassword,
		CreatedAt: time.Now(),
		CreatedBy: userID,
	}

	err = newUser.Validate()

	return
}

func (ur *UserRegister) Validate() (err error) {
	validator := shared.GetValidator()
	return validator.Struct(ur)
}

func (ur UserRegister) ToResponseFormat() RegisterResponseFormat {
	resp := RegisterResponseFormat{
		ID:          ur.ID,
		Name:        ur.Name,
		Username:    ur.Username,
		Email:       ur.Email,
		AccessToken: ur.AccessToken,
	}

	return resp
}

type RegisterRequestFormat struct {
	Username string `json:"username" validate:"required"`
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type RegisterResponseFormat struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	AccessToken string    `json:"accessToken"`
}

// Login
type UserLogin struct {
	ID          uuid.UUID   `db:"id"`
	Name        string      `db:"name"`
	Username    string      `db:"username"`
	Email       string      `db:"email"`
	Password    string      `db:"password" validate:"required"`
	CreatedAt   time.Time   `db:"created_at"`
	CreatedBy   uuid.UUID   `db:"created_by"`
	UpdatedAt   null.Time   `db:"updated_at"`
	UpdatedBy   nuuid.NUUID `db:"updated_by"`
	DeletedAt   null.Time   `db:"deleted_at"`
	DeletedBy   nuuid.NUUID `db:"deleted_by"`
	AccessToken string      `db:"-"`
}

func (ul UserLogin) MarshalJSON() ([]byte, error) {
	return json.Marshal(ul.ToResponseFormat())
}

func (ul UserLogin) LoginUserFromRequestFormat(req LoginRequestFormat) (newLogin UserLogin, err error) {
	if req.Email == "" && req.Username == "" {
		err = errors.New("either username or email is required")
		return
	}

	newLogin = UserLogin{
		Email:    req.Email,
		Username: req.Username,
		Password: req.Password,
	}

	err = newLogin.Validate()
	if err != nil {
		failure.BadRequest(err)
		return
	}

	return
}

func (ul *UserLogin) Validate() (err error) {
	validator := shared.GetValidator()
	return validator.Struct(ul)
}

func (ul *UserLogin) ToResponseFormat() LoginResponseFormat {
	resp := LoginResponseFormat{
		AccessToken: ul.AccessToken,
	}

	return resp
}

type LoginRequestFormat struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password" validate:"required"`
}

type LoginResponseFormat struct {
	AccessToken string `json:"accessToken"`
}
