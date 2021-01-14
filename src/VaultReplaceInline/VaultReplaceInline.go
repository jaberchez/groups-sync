package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

type configuration struct {
	Files []string `yaml:"files"`
}

var (
	regexVault *regexp.Regexp

	vaultHost  string
	vaultToken string
)

func replaceFiles(files []string) (string, error) {
	var output string

	for _, f := range files {
		out, err := replaceFile(f)

		if err != nil {
			return "", err
		}

		output = output + "---\n" + out
	}

	return output, nil
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
			// Get the vault secret path
			res := regexVault.FindStringSubmatch(line)

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

	if len(output) > 1 {
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

	if len(conf.Files) == 0 {
		fmt.Printf("[ERROR] No files found in configuration \"%s\"\n", fileConf)
		os.Exit(1)
	}

	// vault://path-secret@key
	regexVault = regexp.MustCompile(`vault:\/\/(.+)@(\w+)`)

	output, err := replaceFiles(conf.Files)

	if err != nil {
		fmt.Printf("[ERROR] %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("%s\n---\n", output)

	os.Exit(0)
}
