package config

type Config struct {
	AppUrl string `env:"API_URL" env-default:"localhost:8181"`

	DbUser     string `env:"DB_USER" env-default:"def"`
	DbPassword string `env:"DB_PASSWORD"`
	DbAddress  string `env:"DB_ADDRESS"`
	DbPort     string `env:"DB_PORT"`
	DbName     string `env:"DB_NAME"`
}
