package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/evermos/boilerplate-go/internal/domain/user"
	"github.com/evermos/boilerplate-go/shared"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/evermos/boilerplate-go/transport/http/middleware"
	"github.com/evermos/boilerplate-go/transport/http/response"
	"github.com/go-chi/chi"
)

type UserHandler struct {
	UserService    user.UserService
	AuthMiddleware *middleware.Authentication
}

func ProvideUserHandler(userService user.UserService) UserHandler {
	return UserHandler{
		UserService: userService,
	}
}

func (h *UserHandler) Router(r chi.Router) {
	r.Route("/auth", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Post("/register", h.RegisterUser)
			r.Post("/login", h.LoginUser)
		})
	})
}

func (h *UserHandler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var registerRequestFormat user.RegisterRequestFormat
	err := decoder.Decode(&registerRequestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}

	err = shared.GetValidator().Struct(registerRequestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}

	userRegister, err := h.UserService.RegisterUser(registerRequestFormat)
	if err != nil {
		response.WithError(w, err)
		return
	}

	response.WithJSON(w, http.StatusCreated, userRegister)
}

func (h *UserHandler) LoginUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var loginRequestFormat user.LoginRequestFormat
	err := decoder.Decode(&loginRequestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}

	err = shared.GetValidator().Struct(loginRequestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}

	userLogin, err := h.UserService.Login(loginRequestFormat)
	if err != nil {
		response.WithError(w, err)
		return
	}

	response.WithJSON(w, http.StatusOK, userLogin)
}