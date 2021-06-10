package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/logger"
	"github.com/mitchellh/mapstructure"
	"github.com/patrickmn/go-cache"
	"gopkg.in/yaml.v2"
)

//EnvVars - Environment vars struct
type EnvVars struct {
	Port                string
	InventoryProjectID  string
	PrometheusProjectID string
	OperatorProjectID   string
	GitlabToken         string
	GITLAB_API          string
	MailFrom            string
	MailPass            string
	MailDomain          string
	SMTPHost            string
	SMTPPort            string
	DefaultMail         string
	InventoryURL        string
	MonVarsURL          string
	Cache               *cache.Cache
}

//AllHostsFile - file struct
type AllHostsFile struct {
	Prometheus      bool   `yaml:"prometheus"`
	Operator        bool   `yaml:"prometheus_operator"`
	Datacenter      string `yaml:"datacenter"`
	OperatorTargets bool   `yaml:"operator_targets"`
}

//RunPipelineJSON - RunPipelineJSON
type RunPipelineJSON struct {
	Ref       string         `json:"ref"`
	Variables []PipelineVars `json:"variables"`
}

//PipelineVars - PipelineVars
type PipelineVars struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

//GitlabFileGet - gitlab api response
type GitlabFileGet struct {
	FileName      string `json:"file_name"`
	FilePath      string `json:"file_path"`
	Size          int    `json:"size"`
	Encoding      string `json:"encoding"`
	ContentSha256 string `json:"content_sha256"`
	Ref           string `json:"ref"`
	BlobID        string `json:"blob_id"`
	CommitID      string `json:"commit_id"`
	LastCommitID  string `json:"last_commit_id"`
	Content       string `json:"content"`
	Message       string `json:"message"`
	Error         string `json:"error"`
}

//CreatedPipelineData - data structure of answer on pipeline creation
type CreatedPipelineData struct {
	ID int `json:"id"`
}

type PipelineData struct {
	Starter    string
	Branch     string
	ID         string
	ProjectURL string
}

//WebhookData - data structure that is sent on events by gitlab
type WebhookData struct {
	ObjectKind       string `json:"object_kind"`
	Ref              string `json:"ref"`
	UserUsername     string `json:"user_username"`
	ObjectAttributes struct {
		ID     int    `json:"id"`
		Status string `json:"status"`
	} `json:"object_attributes"`
	Commits []struct {
		Message string `json:"message"`
		URL     string `json:"url"`
		Author  struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
		Added    []string `json:"added"`
		Modified []string `json:"modified"`
		Removed  []string `json:"removed"`
	} `json:"commits"`
	Project struct {
		WebURL string `json:"web_url"`
	} `json:"project"`
	TotalCommitsCount int `json:"total_commits_count"`
}

//help
func getEnv(key string, defaultVal string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultVal
}

func checkEnv(k, v string) string {
	if v == "" {
		logger.Fatalf("Key %s no found \n Example: export %s=<value>", k, k)
	}
	return v
}

//GetEnvVars - Get all necessary environment variables
func GetEnvVars() *EnvVars {
	return &EnvVars{
		Port:                getEnv("PORT", "8800"),
		InventoryProjectID:  checkEnv("INV_ID", os.Getenv("INV_ID")),
		PrometheusProjectID: checkEnv("PROM_ID", os.Getenv("PROM_ID")),
		OperatorProjectID:   checkEnv("OP_ID", os.Getenv("OP_ID")),
		GitlabToken:         checkEnv("GIT_TOKEN", os.Getenv("GIT_TOKEN")),
		GITLAB_API:          checkEnv("CI_API_V4_URL", os.Getenv("CI_API_V4_URL")),
		MailFrom:            checkEnv("MAIL_FROM", os.Getenv("MAIL_FROM")),
		MailPass:            getEnv("MAIL_PASS", ""), //checkEnv("MAIL_PASS", os.Getenv("MAIL_PASS")),
		MailDomain:          checkEnv("MAIL_DOMAIN", os.Getenv("MAIL_DOMAIN")),
		SMTPHost:            checkEnv("SMTP_HOST", os.Getenv("SMTP_HOST")),
		SMTPPort:            checkEnv("SMTP_PORT", os.Getenv("SMTP_PORT")),
		DefaultMail:         checkEnv("DEFAULT_MAIL", os.Getenv("DEFAULT_MAIL")),
		InventoryURL:        checkEnv("INV_URL", os.Getenv("INV_URL")),
		MonVarsURL:          checkEnv("MON_URL", os.Getenv("MON_URL")),
		Cache:               cache.New(5*time.Minute, 10*time.Minute),
	}
}

//CheckIfMonitored - detect if there is a variable in inventory
func CheckIfMonitored(Vars *EnvVars, BranchName string) *AllHostsFile {
	GitlabAPIResponse := new(GitlabFileGet)
	GitFile := new(AllHostsFile)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	GitlabURL := fmt.Sprintf("%s/projects/%s/repository/files/", Vars.GITLAB_API, Vars.InventoryProjectID)
	GitlabURL += "group_vars%2Fall_hosts.yml"
	request, _ := http.NewRequest("GET", GitlabURL, nil)
	request.Header.Set("PRIVATE-TOKEN", Vars.GitlabToken)
	query := request.URL.Query()
	query.Add("ref", BranchName)
	request.URL.RawQuery = query.Encode()
	response, err := client.Do(request)
	if err != nil {
		logger.Infof("Error getting response from gitlab: %v", err)
		return GitFile
	}
	errJS := json.NewDecoder(response.Body).Decode(GitlabAPIResponse)
	if errJS != nil {
		logger.Infof("Error decoding gitlab response: %v", err)
		return GitFile
	}
	FileContent, err := base64.StdEncoding.DecodeString(GitlabAPIResponse.Content)
	if err != nil {
		logger.Infof("%s", err)
		return GitFile
	}
	defer response.Body.Close()
	errUM := yaml.Unmarshal(FileContent, &GitFile)
	if errUM != nil {
		logger.Infof("Error unmarshaling all_hosts file: %s", errUM)
		return GitFile
	}
	return GitFile
}

//RunPipeline RunPipeline
func RunPipeline(Vars *EnvVars, BranchName string, gitFile AllHostsFile, project string) int {
	GitlabAPIResponse := new(CreatedPipelineData)
	var gitPipelineURI string
	PipeJSON := new(RunPipelineJSON)
	PipeJSON.Ref = "master"
	switch project {
	case "prometheus":
		gitPipelineURI = fmt.Sprintf("%s/projects/%s/pipeline", Vars.GITLAB_API, Vars.PrometheusProjectID)
		PipeJSON.Variables = []PipelineVars{
			{Key: "LANDSCAPE", Value: BranchName},
		}
	case "operator":
		gitPipelineURI = fmt.Sprintf("%s/projects/%s/pipeline", Vars.GITLAB_API, Vars.OperatorProjectID)
		switch gitFile.Datacenter {
		case "":
			PipeJSON.Variables = []PipelineVars{
				{Key: "LANDSCAPE", Value: BranchName},
				{Key: "TARGETS", Value: strconv.FormatBool(gitFile.OperatorTargets)},
			}

		default:
			PipeJSON.Variables = []PipelineVars{
				{Key: "LANDSCAPE", Value: BranchName},
				{Key: "ENV", Value: gitFile.Datacenter},
				{Key: "TARGETS", Value: strconv.FormatBool(gitFile.OperatorTargets)},
			}
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	DataSend, _ := json.Marshal(PipeJSON)
	request, err := http.NewRequest("POST", gitPipelineURI, bytes.NewBuffer(DataSend))
	request.Header.Set("PRIVATE-TOKEN", Vars.GitlabToken)
	request.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	errDecode := json.NewDecoder(resp.Body).Decode(&GitlabAPIResponse)
	if errDecode != nil {
		logger.Infof("Could not decode pipline data: %v", errDecode.Error())
	}
	defer resp.Body.Close()
	return GitlabAPIResponse.ID
}

//ProcWebHook - process sent data
func (Vars *EnvVars) ProcWebHook(resp http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(resp, "Method is not supported. Should be a post with json body.", http.StatusNotFound)
		return
	}
	WebHookData := new(WebhookData)
	err := json.NewDecoder(req.Body).Decode(&WebHookData)
	if err != nil {
		logger.Infof("Could not decode webhook data: %v", err.Error())
		http.Error(resp, err.Error(), http.StatusBadRequest)
		return
	}
	if WebHookData.ObjectKind == "push" {
		RefsSplitted := strings.Split(WebHookData.Ref, "/")
		var PipelineID int
		BranchName := RefsSplitted[len(RefsSplitted)-1]
		gitFile := CheckIfMonitored(Vars, BranchName)
		StarterEmail := fmt.Sprintf("%s@%s", WebHookData.UserUsername, Vars.MailDomain)
		if gitFile.Prometheus {
			logger.Infof("Branch %s is monitored by prometheus, starting prometheus pipeline.", BranchName)
			PipelineID = RunPipeline(Vars, BranchName, *gitFile, "prometheus")
			PipelineIDAsString := fmt.Sprintf("%v", PipelineID)
			PipelineData := PipelineData{
				Starter: StarterEmail,
				Branch:  BranchName,
				ID:      PipelineIDAsString,
			}
			Vars.Cache.Set(PipelineIDAsString, PipelineData, cache.DefaultExpiration)
			logger.Infof("User %s started prometheus pipeline %s", StarterEmail, PipelineIDAsString)
		} else {
			logger.Infof("Branch %s is not monitored by prometheus, bypassing.", BranchName)
		}
		if gitFile.Operator {
			logger.Infof("Branch %s is monitored by prometheus operator, starting prometheus operator pipeline.", BranchName)
			PipelineID = RunPipeline(Vars, BranchName, *gitFile, "operator")
			PipelineIDAsString := fmt.Sprintf("%v", PipelineID)
			PipelineData := PipelineData{
				Starter: StarterEmail,
				Branch:  BranchName,
				ID:      PipelineIDAsString,
			}
			Vars.Cache.Set(PipelineIDAsString, PipelineData, cache.DefaultExpiration)
			logger.Infof("User %s started prometheus operator pipeline %s", StarterEmail, PipelineIDAsString)
		} else {
			logger.Infof("Branch %s is not monitored by prometheus operator, bypassing.", BranchName)
		}
	} else if WebHookData.ObjectKind == "pipeline" {
		PipelineStatus := WebHookData.ObjectAttributes.Status
		logger.Infof("Pipeline status changed: %s", PipelineStatus)
		if PipelineStatus == "failed" {
			PipelineIDAsString := fmt.Sprintf("%v", WebHookData.ObjectAttributes.ID)
			P, found := Vars.Cache.Get(PipelineIDAsString)
			if found {
				PipelineData := PipelineData{}
				PipelineData.ProjectURL = WebHookData.Project.WebURL
				mapstructure.Decode(P, &PipelineData)
				logger.Infof("Found data in cache: user %s started pipline %s", PipelineData.Starter, PipelineIDAsString)
				sendMail(Vars, PipelineData)
			} else {
				PipelineData := PipelineData{
					Starter:    Vars.DefaultMail,
					Branch:     "master",
					ID:         PipelineIDAsString,
					ProjectURL: WebHookData.Project.WebURL,
				}
				sendMail(Vars, PipelineData)
			}
		}
	}
}

func sendMail(Vars *EnvVars, data PipelineData) {
	from := Vars.MailFrom
	password := Vars.MailPass
	if password == "" {
		logger.Infof("Error sending email - empty MAIL_PASS env variable.")
		return
	}
	to := []string{
		data.Starter,
	}
	smtpHost := Vars.SMTPHost
	smtpPort := Vars.SMTPPort

	auth := smtp.PlainAuth("", from, password, smtpHost)
	var body bytes.Buffer
	mimeHeaders := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body.Write([]byte(fmt.Sprintf("Subject: Gitlab monitoring pipeline failed!\n%s\n\n", mimeHeaders)))
	t, _ := template.ParseFiles("/etc/pipestarter/template.html")
	t.Execute(&body, struct {
		PipelineID   string
		Branch       string
		ProjectURL   string
		InventoryURL string
		MonVarsURL   string
	}{
		PipelineID:   data.ID,
		Branch:       data.Branch,
		ProjectURL:   data.ProjectURL,
		InventoryURL: Vars.InventoryURL,
		MonVarsURL:   Vars.MonVarsURL,
	})
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, body.Bytes())
	if err != nil {
		logger.Infof("Error sending email %s.", err)
		return
	}
}

func (Vars *EnvVars) healthcheck(resp http.ResponseWriter, req *http.Request) {
	_, _ = fmt.Fprintf(resp, "OK")
	return
}

func main() {
	Vars := GetEnvVars()
	mux := http.NewServeMux()
	mux.HandleFunc("/gitlab", Vars.ProcWebHook)
	mux.HandleFunc("/healthcheck", Vars.healthcheck)
	logger.Infof("start listen port: %s", Vars.Port)
	errors := http.ListenAndServe(":"+Vars.Port, mux)
	logger.Infof("%v", errors)
}
