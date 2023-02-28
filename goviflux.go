package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cblomart/goviflux/config"
	"github.com/cblomart/goviflux/vicare"

	client "github.com/influxdata/influxdb1-client/v2"
	"github.com/takama/daemon"
)

const (
	VICARE_BASE = "https://api.viessmann.com/iot/v1/"
)

var (
	conf         = &config.Config{}
	vicareclient *vicare.ViCare
	influx       client.Client
	points       = []*client.Point{}
	dependencies = []string{}
)

// function to collect data
func collect() {
	log.Println("retrieving data from viessmann")
	t := time.Now()
	for _, device := range conf.Collect {
		features, err := vicareclient.GetFeaturesFiltered(device.InstallationId, device.GatewaySerial, device.DeviceId, device.Features)
		if err != nil {
			log.Printf("could not collect features for device: installation id=%d; gateway serial=%s; device id=%s: %s\n", device.InstallationId, device.GatewaySerial, device.DeviceId, err)
		}
		for _, feature := range features {
			if feature.Properties.Value != nil {
				point, err := client.NewPoint(
					feature.Feature,
					map[string]string{
						"installationId": strconv.Itoa(device.InstallationId),
						"gatewaySerial":  device.GatewaySerial,
						"deviceId":       device.DeviceId,
						"unit":           feature.Properties.Value.Unit,
						"type":           feature.Properties.Value.Type,
					},
					map[string]interface{}{
						"value": feature.Properties.Value.Value,
					},
					t,
				)
				if err != nil {
					log.Printf("could not create point from %s", feature.Feature)
				}
				points = append(points, point)
			}
			if feature.Properties.CurrentDay != nil {
				point, err := client.NewPoint(
					feature.Feature,
					map[string]string{
						"installationId": strconv.Itoa(device.InstallationId),
						"gatewaySerial":  device.GatewaySerial,
						"deviceId":       device.DeviceId,
						"unit":           feature.Properties.CurrentDay.Unit,
						"type":           feature.Properties.CurrentDay.Type,
					},
					map[string]interface{}{
						"currentDay":    feature.Properties.CurrentDay.Value,
						"currentMonth":  feature.Properties.CurrentMonth.Value,
						"currentYear":   feature.Properties.CurrentYear.Value,
						"lastSevenDays": feature.Properties.LastSevenDays.Value,
					},
					t,
				)
				if err != nil {
					log.Printf("could not create point from %s", feature.Feature)
				}
				points = append(points, point)

			}
		}
		bps, err := client.NewBatchPoints(client.BatchPointsConfig{
			Precision:       "s",
			Database:        conf.Influx.Database,
			RetentionPolicy: "default",
		})
		bps.AddPoints(points)
		if err != nil {
			log.Println("cloud not create batchpoints")
			points = nil
			continue
		}
		err = influx.Write(bps)
		if err != nil {
			log.Printf("cloud not wirte to influx: %s", err)
			points = nil
			continue
		}
		log.Printf("written %d points to influx", len(points))
		points = nil
	}
}

// Service has embedded daemon
type Service struct {
	daemon.Daemon
}

func (service *Service) Manage() (string, error) {

	usage := "Usage: goviflux install | remove | start | stop | status"

	// if received any kind of command, do it
	if len(os.Args) > 1 {
		command := os.Args[1]
		switch command {
		case "install":
			return service.Install()
		case "remove":
			return service.Remove()
		case "start":
			return service.Start()
		case "stop":
			return service.Stop()
		case "status":
			return service.Status()
		case "list":
			// create the vicare client
			vicareclient, err := vicare.ConfigToViCare(conf)
			if err != nil {
				return fmt.Sprintf("could not instanciate vicare client"), err
			}
			instalations, err := vicareclient.GetInstalations()
			if err != nil {
				return fmt.Sprintf("could list vicare instalations"), err
			}
			gateways, err := vicareclient.GetGateways()
			if err != nil {
				return fmt.Sprintf("could list vicare instalations"), err
			}
			output := "list info:\n"
			output += fmt.Sprintf("Instalation\tInstallationID\tGatewaySerial\tDeviceID\tDeviceType\tFeature\n")
			for _, gateway := range gateways {
				for _, instalation := range instalations {
					if gateway.InstallationId != instalation.Id {
						continue
					}
					devices, err := vicareclient.GetDevices(instalation.Id, gateway.Serial)
					if err != nil {
						log.Printf("failed to get device (id: %d; serial: %s): %s", instalation.Id, gateway.Serial, err)
					}
					for _, device := range devices {
						features, err := vicareclient.GetFeatures(instalation.Id, gateway.Serial, device.Id)
						if err != nil {
							log.Printf("failed to get device features (id: %d; serial: %s; device: %s): %s", instalation.Id, gateway.Serial, device.Id, err)
						}
						for _, feature := range features {
							output += fmt.Sprintf("%s\t%d\t%s\t%s\t%s\t%s\n", instalation.Description, instalation.Id, gateway.Serial, device.Id, device.DeviceType, feature.Feature)
						}
					}
				}
			}
			return output, nil
		default:
			return usage, nil
		}
	}

	// create a ticker for duration
	ticker := time.NewTicker(conf.Period.Duration)
	defer ticker.Stop()

	// create a channel for system interupt
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, os.Kill, syscall.SIGTERM)

	// create the vicare client
	var err error
	vicareclient, err = vicare.ConfigToViCare(conf)
	if err != nil {
		return fmt.Sprintf("could not instanciate vicare client"), err
	}

	// preparing the influx connection
	influx, err = client.NewHTTPClient(client.HTTPConfig{
		Addr:     conf.Influx.Url,
		Username: conf.Username,
		Password: conf.Password,
	})
	if err != nil {
		return fmt.Sprintf("could not instanciate the influx client"), err
	}
	_, ver, err := influx.Ping(5 * time.Second)
	if err != nil {
		return fmt.Sprintf("test connection to influx failed"), err
	}
	log.Printf("connected to influx %s (%s)", conf.Influx.Url, ver)
	defer influx.Close()

	//initial collection
	collect()

	for {
		select {
		case <-ticker.C:
			collect()
		case killSignal := <-interrupt:
			log.Println("Got signal:", killSignal)
			if killSignal == os.Interrupt {
				return "Daemon was interrupted by system signal", nil
			}
			return "Daemon was killed", nil
		}
	}
}

func main() {
	log.Println("Viessmann logger to influx db")
	// initialize config
	// find config file location
	basename := path.Base(os.Args[0])
	configname := strings.TrimSuffix(basename, filepath.Ext(basename))
	location := fmt.Sprintf("/etc/%s.json", configname)
	if _, err := os.Stat(location); err != nil {
		location = fmt.Sprintf("%s.json", configname)
		if _, err := os.Stat(location); err != nil {
			log.Fatalf("no configuraiton file in '.' or '/etc'")
		}
	}

	// read the configuration
	file, err := os.Open(location)
	if err != nil {
		log.Fatalf("could not open configuration file: %s", location)
	}
	jsondec := json.NewDecoder(file)
	err = jsondec.Decode(conf)
	if err != nil {
		log.Fatalf("could not decode configuration file: %s", location)
	}

	// check token cache path
	if len(conf.RefreshTokenPath) == 0 {
		conf.RefreshTokenPath = fmt.Sprintf("%s.token", configname)
	}

	// create token cache if file does not exist
	refreshTokenPath, err := os.Stat(conf.RefreshTokenPath)
	if os.IsNotExist(err) {
		file, err := os.Create(conf.RefreshTokenPath)
		if err != nil {
			log.Fatalf("could not create file: %s", conf.RefreshTokenPath)
		}
		err = file.Chmod(os.FileMode(int(0600)))
		if err != nil {
			log.Fatalf("could not set file mode to 0600: %s", conf.RefreshTokenPath)
		}
		file.Close()
	} else if refreshTokenPath.Mode() != os.FileMode(int(0600)) && runtime.GOOS != "windows" {
		// on windows token will be protected by DPAPI
		log.Fatalf("token cache should have 0600 mode: %s", conf.RefreshTokenPath)
	}

	// create the daemon
	srv, err := daemon.New("goviflux", "Viessmann logger to influx", daemon.SystemDaemon, dependencies...)
	if err != nil {
		log.Println("Error: ", err)
		os.Exit(1)
	}
	service := &Service{srv}
	status, err := service.Manage()
	if err != nil {
		log.Println("Error: ", err)
		os.Exit(1)
	}
	log.Println(status)
}
