package user

import (
	"database/sql"

	"github.com/evermos/boilerplate-go/infras"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/evermos/boilerplate-go/shared/logger"
	"github.com/gofrs/uuid"
	"github.com/jmoiron/sqlx"
)

var (
	userQueries = struct {
		selectUser string
		insertUser string
		// updateUser string
	}{
		selectUser: `
			SELECT
				id,
				name,
				username,
				password,
				email,
				created_at,
				created_by,
				updated_at,
				updated_by,
				deleted_at,
				deleted_by
			FROM user
		`,

		insertUser: `
			INSERT INTO user (
				id,
				name,
				username,
				password,
				email,
				created_at,
				created_by,
				updated_at,
				updated_by,
				deleted_at,
				deleted_by
			) VALUES (
				:id,
				:name,
				:username,
				:password,
				:email,
				:created_at,
				:created_by,
				:updated_at,
				:updated_by,
				:deleted_at,
				:deleted_by
			)
		`,

		// updateUser: `
		// 	UPDATE users
		// 	SET
		// 		username = :username,
		// 		name = :name,
		// 		role = :role,
		// 		created_at = :created_at,
		// 		created_by = :created_by,
		// 		updated_at = :updated_at,
		// 		updated_by = :updated_by,
		// 		deleted_at = :deleted_at,
		// 		deleted_by = :deleted_by
		// 	WHERE
		// 		id = :id
		// `,
	}
)

type UserRepository interface {
	CreateUser(ur UserRegister) (err error)
	ResolveLoginByEmail(email string) (user UserLogin, err error)
	ResolveLoginByUsername(username string) (user UserLogin, err error)
}

type UserRepositoryMySQL struct {
	DB *infras.MySQLConn
}

func ProvideUserRepositoryMySQL(db *infras.MySQLConn) *UserRepositoryMySQL {
	s := new(UserRepositoryMySQL)
	s.DB = db

	return s
}

func (r *UserRepositoryMySQL) CreateUser(userRegister UserRegister) (err error) {
	exists, err := r.ExistsByID(userRegister.ID)
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}

	if exists {
		err = failure.Conflict("create", "userId", "already exists")
		logger.ErrorWithStack(err)
		return
	}

	exists, err = r.ExistByEmail(userRegister.Email)
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}

	if exists {
		err = failure.Conflict("create", "email", "already exists")
		logger.ErrorWithStack(err)
		return
	}

	exists, err = r.ExistByUsername(userRegister.Username)
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}

	if exists {
		err = failure.Conflict("create", "username", "already exists")
		logger.ErrorWithStack(err)
		return
	}

	return r.DB.WithTransaction(func(tx *sqlx.Tx, e chan error) {
		if err := r.txCreate(tx, userRegister); err != nil {
			e <- err
			return
		}

		e <- nil
	})
}

func (r *UserRepositoryMySQL) ResolveLoginByEmail(email string) (user UserLogin, err error) {
	err = r.DB.Read.Get(
		&user,
		userQueries.selectUser+" WHERE email = ?",
		email)

	if err != nil && err == sql.ErrNoRows {
		err = failure.NotFound("user")
		logger.ErrorWithStack(err)
		return
	}

	return
}

func (r *UserRepositoryMySQL) ResolveLoginByUsername(username string) (user UserLogin, err error) {
	err = r.DB.Read.Get(
		&user,
		userQueries.selectUser+" WHERE username = ?",
		username)

	if err != nil && err == sql.ErrNoRows {
		err = failure.NotFound("user")
		logger.ErrorWithStack(err)
		return
	}

	return
}

// Exists
func (r *UserRepositoryMySQL) ExistsByID(id uuid.UUID) (exists bool, err error) {
	err = r.DB.Read.Get(
		&exists,
		"SELECT COUNT(id) FROM user WHERE id = ?",
		id.String())

	if err != nil {
		logger.ErrorWithStack(err)
	}

	return
}

func (r *UserRepositoryMySQL) ExistByEmail(email string) (exists bool, err error) {
	err = r.DB.Read.Get(
		&exists,
		"SELECT COUNT(username) FROM user WHERE email = ?",
		email)

	if err != nil {
		logger.ErrorWithStack(err)
	}

	return
}

func (r *UserRepositoryMySQL) ExistByUsername(username string) (exists bool, err error) {
	err = r.DB.Read.Get(
		&exists,
		"SELECT COUNT(username) FROM user WHERE username = ?",
		username)

	if err != nil {
		logger.ErrorWithStack(err)
	}

	return
}

// Transactions
func (r *UserRepositoryMySQL) txCreate(tx *sqlx.Tx, userRegister UserRegister) (err error) {
	stmt, err := tx.PrepareNamed(userQueries.insertUser)
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(userRegister)
	if err != nil {
		logger.ErrorWithStack(err)
	}

	return
}
