package domain

import (
	"database/sql"
	"github.com/bohdanstryber/banking-go/errs"
	"github.com/bohdanstryber/banking-go/logger"
	"github.com/jmoiron/sqlx"
)

type AuthRepository interface {
	FindBy(username string, password string) (*Login, *errs.AppError)
	GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError)
	RefreshTokenExists(token string) *errs.AppError
}

type AuthRepositoryDb struct {
	client *sqlx.DB
}

func (d AuthRepositoryDb) FindBy(username string, password string) (*Login, *errs.AppError) {
	var login Login
	sqlQuery := `SELECT username, u.customer_id, role, group_concat(a.account_id) as account_numbers
		FROM users u 
		    LEFT JOIN accounts a ON a.customer_id = u.customer_id
		WHERE username = ? AND password = ?
		GROUP BY u.customer_id`

	err := d.client.Get(&login, sqlQuery, username, password)

	if err != nil {
		if err != sql.ErrNoRows {
			return nil, errs.NewAuthenticationError("invalid credentials")
		} else {
			logger.Error("Error while verifying login request from database: " + err.Error())

			return nil, errs.NewUnexpectedError("Unexpected database error")
		}
	}

	return &login, nil
}

func (d AuthRepositoryDb) GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError) {
	var appErr *errs.AppError
	var refreshToken string

	if refreshToken, appErr = authToken.newRefreshToken(); appErr != nil {
		return "", appErr
	}

	sqlInsert := "INSERT INTO refresh_token_store (refresh_token) values (?)"
	_, err := d.client.Exec(sqlInsert, refreshToken)
	if err != nil {
		logger.Error("Unexpected database error: " + err.Error())

		return "", errs.NewUnexpectedError("Unexpected database error")
	}

	return refreshToken, nil
}

func (d AuthRepositoryDb) RefreshTokenExists(refreshToken string) *errs.AppError {
	sqlSelect := "SELECT refresh_token FROM refresh_token_store WHERE refresh_token = ?"
	var token string
	err := d.client.Get(&token, sqlSelect, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errs.NewAuthenticationError("Refresh token not registered in the store")
		} else {
			logger.Error("Unexpected database error: " + err.Error())

			return errs.NewUnexpectedError("Unexpected database error")
		}
	}

	return nil
}

func NewAuthRepository(client *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{client}
}
