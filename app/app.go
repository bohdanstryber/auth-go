package app

import (
	"fmt"
	"github.com/bohdanstryber/auth-go/config"
	"github.com/bohdanstryber/auth-go/domain"
	"github.com/bohdanstryber/auth-go/service"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/jmoiron/sqlx"
	"net/http"
	"time"
)

var cnfg config.Config

func Start() {
	err := cleanenv.ReadConfig(".env", &cnfg)
	if err != nil {
		panic("Config file is not defined")
	}

	router := mux.NewRouter()
	authRepository := domain.NewAuthRepository(getDbClient())

	ah := AuthHandler{service.NewLoginService(authRepository, domain.GetRolePermissions())}

	router.HandleFunc("/auth/login", ah.Login).Methods(http.MethodPost)
	//@TODO: Add sign up
	router.HandleFunc("/auth/refresh", ah.Refresh).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", ah.Verify).Methods(http.MethodGet)

	http.ListenAndServe(cnfg.AppUrl, router)
}

func getDbClient() *sqlx.DB {
	dataSource := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		cnfg.DbUser,
		cnfg.DbPassword,
		cnfg.DbAddress,
		cnfg.DbPort,
		cnfg.DbName)
	client, err := sqlx.Open("mysql", dataSource)

	if err != nil {
		panic(err)
	}
	// See "Important settings" section.
	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)

	return client
}
