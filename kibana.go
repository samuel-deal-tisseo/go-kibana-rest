package kibana

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-resty/resty/v2"
	"github.com/samuel-deal-tisseo/go-kibana-rest/v7/kbapi"
)

type AuthMethodEnum int

const (
	AUTH_BASIC AuthMethodEnum = 0
	AUTH_FORM  AuthMethodEnum = 1
)

// Config contain the value to access on Kibana API
type Config struct {
	Address          string
	Username         string
	Password         string
	DisableVerifySSL bool
	CAs              []string
	AuthMethod       AuthMethodEnum
}

// Client contain the REST client and the API specification
type Client struct {
	*kbapi.API
	Client     *resty.Client
	AuthMethod AuthMethodEnum
}

// NewDefaultClient init client with empty config
func NewDefaultClient() (*Client, error) {
	return NewClient(Config{})
}

// NewClient init client with custom config
func NewClient(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		cfg.Address = "http://localhost:5601"
	}

	restyClient := resty.New().
		SetHostURL(cfg.Address).
		SetHeader("kbn-xsrf", "true").
		SetHeader("Content-Type", "application/json")
	if cfg.AuthMethod == AUTH_BASIC {
		restyClient.SetBasicAuth(cfg.Username, cfg.Password)
	}

	for _, path := range cfg.CAs {
		restyClient.SetRootCertificate(path)
	}

	client := &Client{
		Client:     restyClient,
		API:        kbapi.New(restyClient),
		AuthMethod: cfg.AuthMethod,
	}

	if cfg.DisableVerifySSL == true {
		client.Client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}
	if cfg.AuthMethod == AUTH_FORM {
		err := initFormAuth(client, cfg)
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

func initFormAuth(client *Client, cfg Config) error {
	const browserAccept = `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8`

	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client.Client.SetCookieJar(jar)
	httpClient := http.Client{
		Timeout: time.Duration(1) * time.Second,
		Jar:     jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", cfg.Address, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Accept", browserAccept)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	} else if resp.StatusCode >= 400 {
		return errors.New("First request failed")
	}
	loginRedirectUrl, err := resp.Location()
	if err != nil {
		return err
	}
	formReq, err := http.NewRequest("GET", loginRedirectUrl.String(), nil)
	formResp, err := httpClient.Do(formReq)
	if err != nil {
		return err
	}
	defer formResp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(bufio.NewReader(formResp.Body))
	if err != nil {
		return err
	}
	form := doc.Find("form").First()
	postUrl, ok := form.Attr("action")
	if !ok {
		return errors.New("No login form detected")
	}
	data := url.Values{}
	form.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}
		value, _ := s.Attr("value")
		data.Set(name, value)
	})
	data.Set("username", cfg.Username)
	data.Set("password", cfg.Password)
	loginReq, err := http.NewRequest("POST", postUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	loginReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	followRedirectClient := http.Client{
		Timeout: time.Duration(1) * time.Second,
		Jar:     jar,
	}
	loginResp, err := followRedirectClient.Do(loginReq)
	if err != nil {
		return err
	}
	loginResp.Body.Close()
	return nil
}
