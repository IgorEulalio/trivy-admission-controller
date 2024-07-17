package config

import (
	"log"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

type RedisConfig struct {
	Address  string `mapstructure:"address"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"database"`
}

type LocalCacheConfig struct {
	Expiration int `mapstructure:"expiration"`
	MaxSize    int `mapstructure:"max_size"`
}

type CacheConfig struct {
	RedisConfig RedisConfig      `mapstructure:"redis"`
	LocalConfig LocalCacheConfig `mapstructure:"local"`
}

type Config struct {
	Port        int         `mapstructure:"port"`
	CacheConfig CacheConfig `mapstructure:"cache"`
	DockerToken string      `mapstructure:"docker_token"`
	OutputDir   string      `mapstructure:"output_dir"`
	KubeConfig  string      `mapstructure:"kube_config"`
	Namespace   string      `mapstructure:"namespace"`
	CertFile    string      `mapstructure:"tls_cert_file"`
	KeyFile     string      `mapstructure:"tls_key_file"`
	TrivyPath   string      `mapstructure:"trivy_path"`
}

var Cfg Config

func InitConfig() {
	var configFileName, configFilePath string
	configFileName = os.Getenv("CONFIG_FILE_NAME")
	if configFileName == "" {
		configFileName = "config_example.yaml"
	}
	configFilePath = os.Getenv("CONFIG_FILE_PATH")
	if configFilePath == "" {
		configFilePath = "./"
	}
	viper.SetConfigName(configFileName)
	viper.AddConfigPath(configFilePath)
	viper.SetConfigType("yaml")
	// EnvKeyReplacer must be explicitly called before AutomaticEnv
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	setDefaultValues()
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}

	if err := viper.Unmarshal(&Cfg); err != nil {
		log.Fatalf("Unable to decode into struct, %v", err)
	}
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Println("Config file changed:", e.Name)
		if err := viper.Unmarshal(&Cfg); err != nil {
			log.Fatalf("Unable to decode into struct, %v", err)
		}
	})

	viper.WatchConfig()
}

func setDefaultValues() {
	viper.SetDefault("port", 8080)
	viper.SetDefault("cache.local.expiration", 200)
	viper.SetDefault("cache.local.max_size", 5000)
	viper.SetDefault("output_dir", "./")
	viper.SetDefault("namespace", "default")
	viper.SetDefault("trivy_path", "/usr/local/bin/trivy")
}
