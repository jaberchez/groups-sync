package main

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

type configuration struct {
	NameConfigMap string `yaml:"nameConfigMap"`
	NameSpace     string `yaml:"namespace"`
	PathFile      string `yaml:"pathFile"`
}

type openshiftConfigMap struct {
	Name      string
	NameSpace string
	Key       string
	Value     string
}

var (
	regexVault *regexp.Regexp

	vaultHost  string
	vaultToken string
)

var configMapTmpl = `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Name }}
  namespace: {{ .NameSpace }}
data:
{{ .Key | indent 2}}: |
{{ .Value | indent 4 }}
`

func createConfigMap(nameConfigMap, namespace, fileConfigMapData string) error {
	var data openshiftConfigMap
	var tpl bytes.Buffer

	data.Name = nameConfigMap
	data.NameSpace = namespace

	configMapData, err := replaceFile(fileConfigMapData)

	if err != nil {
		return err
	}

	data.Key = filepath.Base(fileConfigMapData)
	data.Value = configMapData

	t := template.Must(template.New("base").Funcs(sprig.FuncMap()).Parse(configMapTmpl))

	err = t.Execute(&tpl, data)

	if err != nil {
		return err
	}

	s := tpl.String()
	s = strings.ReplaceAll(s, "&#34;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")

	fmt.Print(s)

	return nil
}

func replaceFile(file string) (string, error) {
	var output string

	fileSize, err := checkIfFileSize(file)

	if err != nil {
		return "", fmt.Errorf("File error: %v", err)
	}

	if fileSize == 0 {
		return "", nil
	}

	f, err := os.OpenFile(file, os.O_RDONLY, os.ModePerm)

	if err != nil {
		return "", fmt.Errorf("Open file error: %v", err)
	}

	defer f.Close()

	sc := bufio.NewScanner(f)

	for sc.Scan() {
		line := sc.Text() // GET the line string

		if regexVault.MatchString(line) {
			res := regexVault.FindStringSubmatch(line)

			// Get the secret from Vault
			secret, err := getSecret(res[1], res[2])

			if err != nil {
				return "", err
			}

			line = regexVault.ReplaceAllString(line, secret)

			output += line
		} else {
			output += line
		}

		output += "\n"
	}

	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("Scan file error: %v", err)
	}

	if len(output) > 0 {
		// Delete last carriage return
		output = output[:len(output)-1]
	}

	return output, nil
}

func checkIfFileSize(file string) (int64, error) {
	info, err := os.Stat(file)

	if os.IsNotExist(err) {
		return 0, err
	}

	if info.IsDir() {
		return 0, fmt.Errorf("[ERROR] File \"%s\" is a directory", file)
	}

	return info.Size(), nil
}

func getSecret(pathSecret string, key string) (string, error) {
	client, err := createVaultClient()

	if err != nil {
		return "", err
	}

	vaultData, err := client.Logical().Read(pathSecret)

	if err != nil {
		return "", err
	}

	if vaultData == nil {
		// Secret does not exist
		return "", fmt.Errorf("Secret \"%s\" not found", pathSecret)
	}

	v := vaultData.Data["data"]

	if v == nil {
		return "", fmt.Errorf("Data not found")
	}

	d := v.(map[string]interface{})

	for k, v := range d {
		if k == key {
			return v.(string), nil
		}
	}

	return "", fmt.Errorf("Key \"%s\" not found", key)
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

	if err != nil {
		fmt.Printf("Unmarshal yaml file error: %v", err)
		os.Exit(1)
	}

	if len(conf.NameConfigMap) == 0 {
		fmt.Printf("nameConfigMap not found in file configuration \"%s\"\n", fileConf)
		os.Exit(1)
	}

	if len(conf.NameSpace) == 0 {
		fmt.Printf("namespace not found in file configuration \"%s\"\n", fileConf)
		os.Exit(1)
	}

	if len(conf.PathFile) == 0 {
		fmt.Printf("pathFile not found in file configuration \"%s\"\n", fileConf)
		os.Exit(1)
	}

	// vault://path-secret@key
	regexVault = regexp.MustCompile(`vault:\/\/(.+)@(\w+)`)

	if err := createConfigMap(conf.NameConfigMap, conf.NameSpace, conf.PathFile); err != nil {
		fmt.Printf("[ERROR] %s\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}
