package config

import (
	"errors"
	"fmt"
	"github.com/spf13/viper"
)

const (
	DefaultProxyAddr        = "127.0.0.1:9590"
	DefaultRootAddr         = "127.0.0.1:9591"
	DefaultRecursiveAddr    = "127.0.0.1:9592"
	DefaultEthereumEndpoint = "https://mainnet.infura.io/v3/b0933ce6026a4e1e80e89e96a5d095bc"
)

// User Represents user facing configuration
type User struct {
	ProxyAddr        string `mapstructure:"PROXY_ADDRESS"`
	RootAddr         string `mapstructure:"ROOT_ADDRESS"`
	RecursiveAddr    string `mapstructure:"RECURSIVE_ADDRESS"`
	EthereumEndpoint string `mapstructure:"ETHEREUM_ENDPOINT"`
}

var ErrUserConfigNotFound = errors.New("user config not found")

// ReadUserConfig reads user facing configuration
func ReadUserConfig(path string) (config User, err error) {
	// TODO: Viper is likely overkill write a custom loader
	viper.AddConfigPath(path)
	viper.SetConfigName("fingertip.env")
	viper.SetConfigType("env")
	viper.SetEnvPrefix("FINGERTIP")
	viper.AutomaticEnv()

	viper.SetDefault("PROXY_ADDRESS", DefaultProxyAddr)
	viper.SetDefault("ROOT_ADDRESS", DefaultRootAddr)
	viper.SetDefault("RECURSIVE_ADDRESS", DefaultRecursiveAddr)
	viper.SetDefault("ETHEREUM_ENDPOINT", DefaultEthereumEndpoint)

	err = viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			err = fmt.Errorf("error reading user config: %v", err)
			return
		}
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		err = fmt.Errorf("error reading user config: %v", err)
	}
	return
}
