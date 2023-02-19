package config

import (
	"encoding/json"
	"errors"
	"time"
)

type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		d.Duration = time.Duration(value)
		return nil
	case string:
		var err error
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid duration")
	}
}

type CollectFeatures struct {
	InstallationId int
	GatewaySerial  string
	DeviceId       string
	Features       []string
}

type InfluxConfig struct {
	Url      string
	Username string
	Password string
	Database string
}

type Config struct {
	Period           Duration
	Username         string
	Password         string
	ClientId         string
	CallbackUrl      string
	RefreshTokenPath string
	Collect          []CollectFeatures
	Influx           InfluxConfig
}
