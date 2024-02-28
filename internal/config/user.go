package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/viper"
)

const (
	DefaultProxyAddr        = "127.0.0.1:9590"
	DefaultRootAddr         = "127.0.0.1:9591"
	DefaultRecursiveAddr    = "https://hnsdoh.com/dns-query"
	DefaultEthereumEndpoint = "https://mainnet.infura.io/v3/b0933ce6026a4e1e80e89e96a5d095bc"
	DefaultExternalService  = "https://sdaneproofs.htools.work/proofs/"
)

// User Represents user facing configuration
type User struct {
	ProxyAddr        string `mapstructure:"PROXY_ADDRESS"`
	RootAddr         string `mapstructure:"ROOT_ADDRESS"`
	RecursiveAddr    string `mapstructure:"RECURSIVE_ADDRESS"`
	EthereumEndpoint string `mapstructure:"ETHEREUM_ENDPOINT"`
}

// Stored config
type Store struct {
	Version    string `json:"version"`
	AutoConfig bool   `json:"auto_config"`

	path string
}

func readStore(path, version string, old *Store) (*Store, error) {
	var zero *Store
	if old != nil {
		zero = old
	} else {
		zero = &Store{
			AutoConfig: false,
			Version:    version,
			path:       path,
		}
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return zero, nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading app config: %v", err)
	}
	if len(b) == 0 {
		return zero, nil
	}
	if err := json.Unmarshal(b, zero); err != nil {
		return nil, fmt.Errorf("failed parsing app config: %v", err)
	}
	return zero, nil
}

func (i *Store) Reload() error {
	_, err := readStore(i.path, i.Version, i)
	return err
}

func (i *Store) Save() error {
	b, err := json.Marshal(i)
	if err != nil {
		return fmt.Errorf("failed encoding app config: %v", err)
	}

	if err := os.WriteFile(i.path, b, 0664); err != nil {
		return fmt.Errorf("faild writing app config: %v", err)
	}
	return err
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
	viper.SetDefault("EXTERNAL_SERVICE", DefaultExternalService)
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
