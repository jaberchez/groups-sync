package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"encoding/base64"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

type configuration struct {
	NameSecret  string   `yaml:"nameSecret"`
	NameSpace   string   `yaml:"namespace"`
	VaultSecret string   `yaml:"vaultSecret"`
	VaultKeys   []string `yaml:"vaultKeys"`
}

type openshiftSecret struct {
	Name      string
	NameSpace string
	Data      map[string]interface{}
}

var (
	vaultHost  string
	vaultToken string
)

var secretTmpl = `apiVersion: v1
kind: Secret
metadata:
  name: {{ .Name }}
  namespace: {{ .NameSpace }}
type: Opaque
data:
  {{- range $key, $value := .Data }}
  {{ printf "%s: %s" $key $value }}
  {{- end }}
`

func usage() {
	nameApp := path.Base(os.Args[0])

	fmt.Printf("Usage: %s vault/secret name-secret namespace\n\n", nameApp)
	fmt.Println("Example:")
	fmt.Printf("   %s cubbyhole/foo-dev foo-secret foo-dev\n", nameApp)

	os.Exit(1)
}

func createSecret(vaultSecret string, vaultKeys []string, nameSecret string, namespace string) error {
	var data openshiftSecret
	var allKeys bool = false

	for _, d := range vaultKeys {
		if d == "*" {
			allKeys = true
			break
		}
	}

	tempData := make(map[string]interface{})

	data.Name = nameSecret
	data.NameSpace = namespace

	client, err := createVaultClient()

	if err != nil {
		return err
	}

	vaultData, err := client.Logical().Read(vaultSecret)

	if err != nil {
		return err
	}

	if vaultData == nil {
		// Secret not exists
		return fmt.Errorf("Secret %s not exists", vaultSecret)
	}

	v := vaultData.Data["data"]

	if v == nil {
		return fmt.Errorf("Data not found")
	}

	d := v.(map[string]interface{})

	for k, v := range d {
		if allKeys {
			tempData[k] = base64.StdEncoding.EncodeToString([]byte(v.(string)))
		} else {
			// Get the keys selected in configuration file
			for _, k2 := range vaultKeys {
				if k == k2 {
					tempData[k] = base64.StdEncoding.EncodeToString([]byte(v.(string)))
				}
			}
		}
	}

	data.Data = tempData

	t := template.New("fromString")

	t, err = t.Parse(secretTmpl)

	if err != nil {
		return err
	}

	t.Execute(os.Stdout, data)

	return nil
}

func createVaultClient() (*api.Client, error) {
	var httpClient = &http.Client{Timeout: 10 * time.Second}

	client, err := api.NewClient(&api.Config{Address: vaultHost, HttpClient: httpClient})

	if err != nil {
		return nil, err
	}

	client.SetToken(vaultToken)

	return client, nil
}

func main() {
	var conf configuration

	// Get environment variables
	vaultHost = os.Getenv("VAULT_HOST")
	vaultToken = os.Getenv("VAULT_TOKEN")

	if len(vaultHost) == 0 {
		fmt.Println("[ERROR] VAULT_HOST environment variable not found")
		os.Exit(1)
	}

	if len(vaultToken) == 0 {
		fmt.Println("[ERROR] VAULT_TOKEN environment variable not found")
		os.Exit(1)
	}

	if len(os.Args) != 2 {
		// Notes: The file yaml configuration is provided by kustomize
		fmt.Printf("Usage: %s file-conf.yaml\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	fileConf := os.Args[1]

	dat, err := ioutil.ReadFile(fileConf)

	if err != nil {
		fmt.Printf("Open file error %s: %v", fileConf, err)
		os.Exit(1)
	}

	err = yaml.Unmarshal(dat, &conf)

	if err := createSecret(conf.VaultSecret, conf.VaultKeys, conf.NameSecret, conf.NameSpace); err != nil {
		fmt.Printf("[ERROR] %s\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}
